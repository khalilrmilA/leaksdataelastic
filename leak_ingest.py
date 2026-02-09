import os
import re
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

import tldextract
import requests
from elasticsearch import Elasticsearch, helpers
from concurrent.futures import ThreadPoolExecutor

import threading


# =========================
# CONFIG (EDIT THESE)
# =========================
LEAK_ROOT = r"E:\TelegramDownloads\httpst.meCLOUDCASPERLINK"
ES_URL = "http://localhost:9200"
INDEX_NAME = "leaks_data"

MAX_WORKERS = min(8, os.cpu_count() or 4)
print_lock = threading.Lock()


# Optional (only if you want live IP geo lookup)
IPINFO_TOKEN = None  # e.g. "xxxx"

# Only these root files matter (case-insensitive, startswith matching also supported)
ROOT_PRIORITY_FILES = (
    "passwords",
    "information",
    "unique_passwords",
)

# Autofill folder names to consider
AUTOFILL_DIR_NAMES = (
    "Autofill",  # matches "Autofill [@BRADLOGS]"
)

# Autofill files to parse (without extension matching too)
AUTOFILL_FILES_ALLOWLIST = (
    "Google Chrome_Default",
    "Microsoft Edge_Default",
)

# Bulk settings
BULK_SIZE = 2000

es = Elasticsearch(ES_URL)


# =========================
# REGEX
# =========================
PHONE_REGEX = re.compile(r"\+\d[\d\s().-]{6,}\d")
EMAIL_REGEX = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)

# passwords.txt format:
# Soft: Google Chrome (Default)
# Host: https://...
# Login: ...
# Password: ...
PW_BLOCK_SOFT = re.compile(r"^Soft:\s*(.*)$", re.IGNORECASE)
PW_BLOCK_HOST = re.compile(r"^Host:\s*(.*)$", re.IGNORECASE)
PW_BLOCK_LOGIN = re.compile(r"^Login:\s*(.*)$", re.IGNORECASE)
PW_BLOCK_PASS = re.compile(r"^Password:\s*(.*)$", re.IGNORECASE)

# information.txt common fields
INFO_KV = re.compile(r"^([A-Za-z _/-]+):\s*(.*)$")
INFO_IP = re.compile(r"^Ip:\s*(.*)$", re.IGNORECASE)
INFO_COUNTRY = re.compile(r"^Country:\s*(.*)$", re.IGNORECASE)


# =========================
# Elasticsearch index mapping
# =========================
def ensure_index():
    if es.indices.exists(index=INDEX_NAME):
        return

    mapping = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        },
        "mappings": {
            "properties": {
                "doc_type": {"type": "keyword"},  # credential | host_info | autofill
                "timestamp": {"type": "date"},

                "victim_folder": {"type": "keyword"},
                "source_file": {"type": "keyword"},
                "source_path": {"type": "keyword"},

                # From information.txt
                # From information.txt
                "ip": {"type": "ip"},
                "country": {"type": "keyword"},
                "malware_path": {"type": "keyword", "ignore_above": 2048},
                "os": {"type": "keyword"},
                "user_name": {"type": "keyword"},
                "computer_name": {"type": "keyword"},


                # From passwords.txt
                "soft": {"type": "keyword"},
                "host": {"type": "keyword"},
                "domain": {"type": "keyword"},
                "login": {"type": "keyword"},
                "password": {"type": "text"},   # IMPORTANT: keep as text (can be long JSON)
                "password_is_json": {"type": "boolean"},

                # From autofill
                "field": {"type": "keyword"},
                "value": {"type": "text"},
                "value_keyword": {"type": "keyword", "ignore_above": 2048},
                "emails": {"type": "keyword"},
                "phones": {"type": "keyword"},

                # optional geo if you enable ipinfo
                "city": {"type": "keyword"},
            }
        }
    }

    es.indices.create(index=INDEX_NAME, body=mapping)
    print(f"✅ Created index: {INDEX_NAME}")


# =========================
# Helpers
# =========================
def sha1_id(*parts: str) -> str:
    s = "||".join([p or "" for p in parts])
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


def safe_domain(host_or_url: str | None) -> str | None:
    if not host_or_url:
        return None
    try:
        if host_or_url.startswith("android://"):
            return "android-app"
        u = urlparse(host_or_url)
        if u.scheme and u.netloc:
            ext = tldextract.extract(u.netloc)
            dom = ext.registered_domain
            return dom or u.netloc
        # maybe it is already a host
        ext = tldextract.extract(host_or_url)
        return ext.registered_domain or host_or_url
    except Exception:
        return None


def ip_lookup(ip: str | None):
    """Optional enrichment."""
    if not ip or not IPINFO_TOKEN:
        return None, None
    try:
        r = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}", timeout=3)
        if r.status_code == 200:
            data = r.json()
            return data.get("country"), data.get("city")
    except Exception:
        pass
    return None, None


def looks_like_noise(line: str) -> bool:
    """
    Autofill junk often looks like ":r1e: apt" etc.
    Drop lines that start with ":" and contain another ":" very early.
    """
    line = line.strip()
    if not line:
        return True
    if line.startswith(":") and line.count(":") >= 2 and len(line) < 40:
        return True
    return False


# =========================
# Parsing
# =========================
def parse_information_txt(path: str) -> dict:
    info = {}
    try:
        lines = open(path, "r", errors="ignore").read().splitlines()
    except Exception:
        return info

    for ln in lines:
        s = ln.strip()
        if not s:
            continue

        # Explicit fields
        m = INFO_IP.match(s)
        if m:
            info["ip"] = m.group(1).strip()
            continue

        m = INFO_COUNTRY.match(s)
        if m:
            info["country"] = m.group(1).strip()
            continue

        # Generic key:value lines
        mkv = INFO_KV.match(s)
        if mkv:
            k_raw = mkv.group(1).strip()
            v = mkv.group(2).strip()
            k = k_raw.lower().replace(" ", "_")

            # malware executable path
            if k == "path":
                info["malware_path"] = v[:2048]

            # OS
            elif k == "windows":
                info["os"] = v

            # usernames/computer
            elif k in ("user_name", "computer_name"):
                info[k] = v

    return info


def parse_passwords_txt(path: str):
    """
    Yields dict entries for each credential block.
    """
    try:
        lines = open(path, "r", errors="ignore").read().splitlines()
    except Exception:
        return

    soft = host = login = password = None

    def emit():
        nonlocal soft, host, login, password

        if not (host and login is not None and password is not None):
            return

        dom = safe_domain(host)

        pw = password.strip()
        pw_is_json = pw.startswith("{") and pw.endswith("}")

        emails = []
        if login and EMAIL_REGEX.search(login):
            emails = [login.lower()]

        yield {
            "soft": (soft or "").strip() or None,
            "host": host.strip(),
            "domain": dom,
            "login": login.strip(),
            "emails": emails,
            "password": pw,
            "password_is_json": pw_is_json,
        }

    for ln in lines + [""]:  # force flush at end
        s = ln.strip()

        if not s:
            for item in emit():
                yield item
            soft = host = login = password = None
            continue

        m = PW_BLOCK_SOFT.match(s)
        if m:
            soft = m.group(1)
            continue
        m = PW_BLOCK_HOST.match(s)
        if m:
            host = m.group(1)
            continue
        m = PW_BLOCK_LOGIN.match(s)
        if m:
            login = m.group(1)
            continue
        m = PW_BLOCK_PASS.match(s)
        if m:
            password = m.group(1)
            continue


def parse_autofill_txt(path: str):
    """
    Extract only useful autofill: emails/usernames/phones and clean noise.
    Yields dict entries with (field, value, emails[], phones[])
    """
    try:
        lines = open(path, "r", errors="ignore").read().splitlines()
    except Exception:
        return

    for ln in lines:
        raw = ln.strip()
        if looks_like_noise(raw):
            continue

        # try split "key value"
        parts = raw.split(None, 1)
        if len(parts) == 1:
            key, value = "value", parts[0]
        else:
            key, value = parts[0].strip(), parts[1].strip()

        # detect phones/emails in the line
        phones = PHONE_REGEX.findall(raw)
        emails = EMAIL_REGEX.findall(raw)

        # if the key is super weird AND no phone/email, skip
        if key.startswith(":") and not phones and not emails:
            continue

        # Keep only lines that look like identity data
        # (emails/phones) OR common identity fields
        key_l = key.lower()
        key_allow = (
            "email" in key_l
            or "user" in key_l
            or "login" in key_l
            or "ident" in key_l
            or key_l in ("account", "basic_email", "loginfmt")
        )

        if not (phones or emails or key_allow):
            continue

        yield {
            "field": key,
            "value": value,
            "emails": list({e.lower() for e in emails}),
            "phones": list({p.replace(" ", "") for p in phones}),
        }


# =========================
# Folder logic (your requested priority)
# =========================
def find_root_priority_files(victim_dir: str):
    found = {}

    try:
        for root, _, files in os.walk(victim_dir):
            for name in files:
                low = name.lower()
                base = os.path.splitext(low)[0]

                if not low.endswith(".txt"):
                    continue

                full_path = os.path.join(root, name)

                matched = False
                for pref in ROOT_PRIORITY_FILES:
                    if base.startswith(pref):
                        found[pref] = full_path
                        matched = True
                        break

                if not matched:
                    found.setdefault("unknown", []).append(full_path)

    except Exception:
        pass

    return found



def parse_generic_txt(path: str):
    try:
        for ln in open(path, "r", errors="ignore"):
            ln = ln.strip()
            if ln:
                yield ln[:5000]
    except Exception:
        return


def find_autofill_files(victim_dir: str):
    results = []
    try:
        for root, dirs, files in os.walk(victim_dir):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]

            if any(k.lower() in root.lower() for k in AUTOFILL_DIR_NAMES):
                for fn in files:
                    if not fn.lower().endswith(".txt"):
                        continue
                    base = os.path.splitext(fn)[0]
                    if any(base.lower() == a.lower() for a in AUTOFILL_FILES_ALLOWLIST):
                        results.append(os.path.join(root, fn))
    except Exception:
        pass

    return results




# =========================
# Victim directory finder (recursive, robust)
# =========================
SKIP_DIRS = {"cookies", "history"}


def find_victim_dirs(root: str):
    """
    Find ANY directory that contains at least one .txt file
    Ignore Cookies / History everywhere
    """
    victims = set()

    for current, dirs, files in os.walk(root):
        # skip junk dirs
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]

        if any(f.lower().endswith(".txt") for f in files):
            victims.add(current)

    return sorted(victims)

def log_dir(msg):
    print(msg, flush=True)

# =========================
# Ingest
# =========================
def process_passwords(pw_path, info_context, victim_name, victim_dir):
    local_actions = []

    for cred in parse_passwords_txt(pw_path):
        doc = {
            "doc_type": "credential",
            "timestamp": datetime.now(timezone.utc),
            "victim_folder": victim_name,
            "source_file": os.path.basename(pw_path),
            "source_path": victim_dir,
            "ip": info_context.get("ip"),
            "country": info_context.get("country"),
            "os": info_context.get("os"),
            "user_name": info_context.get("user_name"),
            "computer_name": info_context.get("computer_name"),
            **cred,
        }

        _id = sha1_id(
            "credential",
            victim_name,
            doc.get("host") or "",
            doc.get("login") or "",
            doc.get("password") or "",
        )

        local_actions.append({
            "_index": INDEX_NAME,
            "_id": _id,
            "_source": doc
        })

    return local_actions

def ingest():
    ensure_index()

    actions = []
    victim_dirs = find_victim_dirs(LEAK_ROOT)

    print(f"✅ Victim folders found: {len(victim_dirs)}")
    total = len(victim_dirs)
    for idx, victim_dir in enumerate(victim_dirs, 1):
        log_dir(f"\n📂 [{idx}/{total}] Scanning:\n{victim_dir}")
        victim_name = os.path.relpath(victim_dir, LEAK_ROOT)
        root_files = find_root_priority_files(victim_dir)

        # =========================
        # 1) information.txt
        # =========================
        info_context = {}
        if "information" in root_files:
            info_path = root_files["information"]
            info_context = parse_information_txt(info_path)

            doc = {
                "doc_type": "host_info",
                "timestamp": datetime.now(timezone.utc),
                "victim_folder": victim_name,
                "source_file": os.path.basename(info_path),
                "source_path": victim_dir,
                **info_context,
            }

            _id = sha1_id("host_info", victim_name, info_path)
            actions.append({
                "_index": INDEX_NAME,
                "_id": _id,
                "_source": doc
            })

        # =========================
        # 2) passwords.txt
        # =========================
        if "passwords" in root_files:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                future = executor.submit(
                    process_passwords,
                    root_files["passwords"],
                    info_context,
                    victim_name,
                    victim_dir
                )
                actions.extend(future.result())

                # =========================
                # 2b) unknown txt files (once per directory)
                # =========================
        #if "unknown" in root_files:
         #   for txt in root_files["unknown"]:
          #      for line in parse_generic_txt(txt):
           #         doc = {
            #            "doc_type": "raw_txt",
             #           "timestamp": datetime.now(timezone.utc),
              #          "victim_folder": victim_name,
               ##         "source_file": os.path.basename(txt),
                 #       "source_path": victim_dir,
                  #      "value": line,
                   # }
#
 ##                   _id = sha1_id("raw_txt", victim_name, txt, line)
#
 #                   actions.append({
  #                      "_index": INDEX_NAME,
   #                     "_id": _id,
    ####                    "_source": doc
        #            })



        # =========================
        # 3) Autofill (ONCE per victim)
        # =========================
        autofill_files = find_autofill_files(victim_dir)
        for af_path in autofill_files:
            for item in parse_autofill_txt(af_path):
                doc = {
                    "doc_type": "autofill",
                    "timestamp": datetime.now(timezone.utc),
                    "victim_folder": victim_name,
                    "source_file": os.path.basename(af_path),
                    "source_path": os.path.dirname(af_path),
                    "field": item["field"],
                    "value": item["value"],
                    "value_keyword": item["value"][:2048],
                    "emails": item["emails"],
                    "phones": item["phones"],
                }

                _id = sha1_id(
                    "autofill",
                    victim_name,
                    doc["source_file"],
                    doc["field"],
                    doc["value"],
                )

                actions.append({
                    "_index": INDEX_NAME,
                    "_id": _id,
                    "_source": doc
                })
        flush_bulk(actions)
        log_dir(f"✅ Finished & pushed: {victim_name}")
        # =========================
        # Bulk flush
        # =========================




def flush_bulk(actions):
    if not actions:
        return
    try:
        helpers.bulk(es, actions, raise_on_error=False, request_timeout=120)
    except Exception as e:
        # Print a helpful message instead of crashing
        print(f"⚠️ Bulk insert error: {e}")
    finally:
        actions.clear()


if __name__ == "__main__":
    ingest()
