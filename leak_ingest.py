import os
import re
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

import tldextract
import requests
from tqdm import tqdm
from elasticsearch import Elasticsearch, helpers

# =========================
# CONFIG (EDIT THESE)
# =========================
LEAK_ROOT = r"E:\TelegramDownloads\@BRADMAX"
ES_URL = "http://localhost:9200"
INDEX_NAME = "leaks_data"

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
        if host and login is not None and password is not None:
            dom = safe_domain(host)
            pw_is_json = False
            pw = password.strip()
            if pw.startswith("{") and pw.endswith("}"):
                pw_is_json = True
            yield {
                "soft": (soft or "").strip() or None,
                "host": host.strip(),
                "domain": dom,
                "login": login.strip(),
                "password": pw,
                "password_is_json": pw_is_json,
            }

    for ln in lines + [""]:  # force flush at end
        s = ln.strip()

        if not s:
            # end of block
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
    """
    Return dict like:
      {"passwords": "...", "information": "..."}
    if found in victim root.
    """
    found = {}

    try:
        for name in os.listdir(victim_dir):
            low = name.lower()
            base = os.path.splitext(low)[0]

            if not low.endswith(".txt"):
                continue

            for pref in ROOT_PRIORITY_FILES:
                if base.startswith(pref):
                    found[pref] = os.path.join(victim_dir, name)
    except Exception:
        pass

    return found


def find_autofill_files(victim_dir: str):
    """
    Find Autofill folder and return allowed txt file paths.
    """
    results = []
    try:
        for name in os.listdir(victim_dir):
            full = os.path.join(victim_dir, name)
            if not os.path.isdir(full):
                continue
            if any(k.lower() in name.lower() for k in AUTOFILL_DIR_NAMES):
                # list files inside autofill folder
                for fn in os.listdir(full):
                    if not fn.lower().endswith(".txt"):
                        continue
                    base = os.path.splitext(fn)[0]
                    if any(base.lower() == a.lower() for a in AUTOFILL_FILES_ALLOWLIST):
                        results.append(os.path.join(full, fn))
    except Exception:
        pass
    return results


# =========================
# Victim directory finder (recursive, robust)
# =========================
def find_victim_dirs(root: str):
    """
    Recursively find directories that contain passwords.txt or information.txt.
    A victim folder is one that contains these marker files.
    """
    victims = set()
    for current, dirs, files in os.walk(root):
        # A victim folder is one that contains passwords.txt or information.txt
        for f in files:
            low = f.lower()
            if low.startswith(("passwords", "information")) and low.endswith(".txt"):
                victims.add(current)
                break
    return sorted(victims)


# =========================
# Ingest
# =========================
def ingest():
    ensure_index()

    actions = []
    victim_dirs = find_victim_dirs(LEAK_ROOT)

    print(f"✅ Victim folders found: {len(victim_dirs)}")

    for victim_dir in tqdm(victim_dirs, desc="Ingesting folders"):
        victim_name = os.path.relpath(victim_dir, LEAK_ROOT)

        root_files = find_root_priority_files(victim_dir)

        # 1) First parse information/passwords in victim root (if present)
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
                **info_context
            }

            _id = sha1_id("host_info", victim_name, info_path)
            actions.append({"_index": INDEX_NAME, "_id": _id, "_source": doc})

        if "passwords" in root_files:
            pw_path = root_files["passwords"]
            for cred in parse_passwords_txt(pw_path):
                # attach ip/country from information.txt if available
                ip = info_context.get("ip")
                country = info_context.get("country")

                # optional: live IP lookup only if enabled
                city = None
                if IPINFO_TOKEN and ip:
                    ctry2, city2 = ip_lookup(ip)
                    country = country or ctry2
                    city = city2

                doc = {
                    "doc_type": "credential",
                    "timestamp": datetime.now(timezone.utc),
                    "victim_folder": victim_name,
                    "source_file": os.path.basename(pw_path),
                    "source_path": victim_dir,
                    "ip": ip,
                    "country": country,
                    "city": city,
                    "os": info_context.get("os"),
                    "user_name": info_context.get("user_name"),
                    "computer_name": info_context.get("computer_name"),
                    **cred
                }

                _id = sha1_id(
                    "credential",
                    victim_name,
                    doc.get("host") or "",
                    doc.get("login") or "",
                    doc.get("password") or ""
                )

                actions.append({"_index": INDEX_NAME, "_id": _id, "_source": doc})

        # If we found either passwords or information, we STOP here (your request)
        if ("passwords" in root_files) or ("information" in root_files):
            pass
        else:
            # 2) Otherwise parse Autofill folder (Google/Microsoft only)
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
                        doc["value"]
                    )
                    actions.append({"_index": INDEX_NAME, "_id": _id, "_source": doc})

        # Flush bulk
        if len(actions) >= BULK_SIZE:
            flush_bulk(actions)

    # final flush
    flush_bulk(actions)
    print("✅ Done.")


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
