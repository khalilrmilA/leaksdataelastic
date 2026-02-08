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
# CONFIG
# =========================
LEAK_ROOT = r"E:\TelegramDownloads\@BRADMAX"
ES_URL = "http://localhost:9200"
INDEX_NAME = "leaks_data"

# Optional IP enrichment
IPINFO_TOKEN = None  # "xxxx"
BULK_SIZE = 2000

# Root priority files (in victim folder root)
ROOT_PRIORITY_FILES = (
    "passwords",
    "information",
    "unique_passwords",
)

# Autofill folder name patterns
AUTOFILL_DIR_NAMES = (
    "autofill",
)

# Autofill filenames allowlist (base name without extension)
# If you want ALL autofill txt files, set this to None.
AUTOFILL_FILES_ALLOWLIST = (
    "google chrome_default",
    "microsoft edge_default",
)

es = Elasticsearch(ES_URL)

# =========================
# REGEX
# =========================
PHONE_REGEX = re.compile(r"\+\d[\d\s().-]{6,}\d")
EMAIL_REGEX = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)

PW_BLOCK_SOFT = re.compile(r"^Soft:\s*(.*)$", re.IGNORECASE)
PW_BLOCK_HOST = re.compile(r"^Host:\s*(.*)$", re.IGNORECASE)
PW_BLOCK_LOGIN = re.compile(r"^Login:\s*(.*)$", re.IGNORECASE)
PW_BLOCK_PASS = re.compile(r"^Password:\s*(.*)$", re.IGNORECASE)

INFO_KV = re.compile(r"^([A-Za-z _/-]+):\s*(.*)$", re.IGNORECASE)


# =========================
# INDEX (create OR extend mapping safely)
# =========================
def ensure_index():
    base_mapping = {
        "properties": {
            "doc_type": {"type": "keyword"},
            "timestamp": {"type": "date"},

            "victim_folder": {"type": "keyword"},
            "source_file": {"type": "keyword"},
            "source_path": {"type": "keyword"},

            "ip": {"type": "ip"},
            "country": {"type": "keyword"},
            "city": {"type": "keyword"},
            "os": {"type": "keyword"},
            "user_name": {"type": "keyword"},
            "computer_name": {"type": "keyword"},
            "malware_path": {"type": "keyword", "ignore_above": 2048},

            "soft": {"type": "keyword"},
            "host": {"type": "keyword"},
            "login_url": {"type": "keyword", "ignore_above": 2048},
            "domain": {"type": "keyword"},
            "login": {"type": "keyword"},
            "emails": {"type": "keyword"},
            "identity_email": {"type": "keyword"},

            "password": {"type": "text"},
            "password_is_json": {"type": "boolean"},
            "pw_len": {"type": "integer"},
            "pw_has_digit": {"type": "boolean"},
            "pw_has_symbol": {"type": "boolean"},

            # autofill
            "field": {"type": "keyword"},
            "value": {"type": "text"},
            "value_keyword": {"type": "keyword", "ignore_above": 2048},
            "phones": {"type": "keyword"},
        }
    }

    if not es.indices.exists(index=INDEX_NAME):
        es.indices.create(
            index=INDEX_NAME,
            body={
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": base_mapping
            }
        )
        print(f"✅ Created index: {INDEX_NAME}")
        return

    # Index exists: add missing fields (safe)
    es.indices.put_mapping(index=INDEX_NAME, body=base_mapping)
    print(f"✅ Index exists, mapping updated (missing fields added): {INDEX_NAME}")


# =========================
# HELPERS
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
        host = u.netloc if (u.scheme and u.netloc) else host_or_url
        ext = tldextract.extract(host)
        return ext.registered_domain or host
    except Exception:
        return None


def ip_lookup(ip: str | None):
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
    line = (line or "").strip()
    if not line:
        return True
    # Typical junk patterns
    if line.startswith(":") and line.count(":") >= 2 and len(line) < 60:
        return True
    return False


def password_features(pw: str) -> dict:
    pw = pw or ""
    return {
        "pw_len": len(pw),
        "pw_has_digit": any(c.isdigit() for c in pw),
        "pw_has_symbol": any((not c.isalnum()) for c in pw),
    }


# =========================
# PARSING
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

        mkv = INFO_KV.match(s)
        if not mkv:
            continue

        k_raw = mkv.group(1).strip()
        v = mkv.group(2).strip()

        k = k_raw.lower().replace(" ", "_")

        if k == "ip":
            info["ip"] = v
        elif k == "country":
            info["country"] = v
        elif k in ("windows", "os"):
            info["os"] = v
        elif k == "user_name":
            info["user_name"] = v
        elif k == "computer_name":
            info["computer_name"] = v
        elif k == "path":
            # Malware executable path
            info["malware_path"] = v[:2048]

    return info


def parse_passwords_txt(path: str):
    try:
        lines = open(path, "r", errors="ignore").read().splitlines()
    except Exception:
        return

    soft = host = login = password = None

    def emit():
        nonlocal soft, host, login, password
        if not host or login is None or password is None:
            return None

        dom = safe_domain(host)
        pw = (password or "").strip()
        pw_is_json = pw.startswith("{") and pw.endswith("}")

        # email extraction from login
        emails = []
        identity_email = None
        if login and EMAIL_REGEX.search(login):
            identity_email = login.strip().lower()
            emails = [identity_email]

        return {
            "soft": (soft or "").strip() or None,
            "host": host.strip(),
            "login_url": host.strip(),      # you asked: url of login page
            "domain": dom,
            "login": (login or "").strip(),
            "emails": emails,
            "identity_email": identity_email,
            "password": pw,
            "password_is_json": pw_is_json,
            **password_features(pw),
        }

    for ln in lines + [""]:
        s = ln.strip()

        if not s:
            item = emit()
            if item:
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
    try:
        lines = open(path, "r", errors="ignore").read().splitlines()
    except Exception:
        return

    for ln in lines:
        raw = (ln or "").strip()
        if looks_like_noise(raw):
            continue

        emails = EMAIL_REGEX.findall(raw)
        phones = PHONE_REGEX.findall(raw)

        # Keep lines that contain useful identity info OR look like key/value identity
        if not emails and not phones:
            # also keep if "email" keyword exists
            if "email" not in raw.lower() and "login" not in raw.lower() and "user" not in raw.lower():
                continue

        parts = raw.split(None, 1)
        if len(parts) == 1:
            field, value = "value", parts[0]
        else:
            field, value = parts[0].strip(), parts[1].strip()

        yield {
            "field": field[:256],
            "value": value,
            "value_keyword": value[:2048],
            "emails": list({e.lower() for e in emails}),
            "phones": list({p.replace(" ", "") for p in phones}),
        }


# =========================
# FILE DISCOVERY
# =========================
def find_root_priority_files(victim_dir: str):
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
    results = []
    try:
        for name in os.listdir(victim_dir):
            full = os.path.join(victim_dir, name)
            if not os.path.isdir(full):
                continue

            if any(k in name.lower() for k in AUTOFILL_DIR_NAMES):
                for fn in os.listdir(full):
                    if not fn.lower().endswith(".txt"):
                        continue

                    base = os.path.splitext(fn)[0].lower()

                    if AUTOFILL_FILES_ALLOWLIST is None:
                        results.append(os.path.join(full, fn))
                    else:
                        if base in AUTOFILL_FILES_ALLOWLIST:
                            results.append(os.path.join(full, fn))
    except Exception:
        pass
    return results


def find_victim_dirs(root: str):
    """
    Fast recursive scan.
    - Stops descending once a victim folder is detected
    - Skips heavy/irrelevant directories
    """
    victims = set()

    SKIP_DIRS = {
        "__pycache__",
        ".git",
        ".idea",
        "node_modules",
        "cache",
        "tmp",
        "logs",
    }

    for current, dirs, files in os.walk(root):
        # --- prune directories early (HUGE SPEEDUP)
        dirs[:] = [
            d for d in dirs
            if d.lower() not in SKIP_DIRS
            and not d.lower().startswith(".")
        ]

        files_low = [f.lower() for f in files]

        has_pw_or_info = any(
            f.endswith(".txt")
            and f.startswith(("passwords", "information", "unique_passwords"))
            for f in files_low
        )

        has_autofill_dir = any("autofill" in d.lower() for d in dirs)

        if has_pw_or_info or has_autofill_dir:
            victims.add(current)

            # 🚀 VERY IMPORTANT:
            # do NOT go deeper once we mark this folder as a victim
            dirs.clear()

    return sorted(victims)


# =========================
# BULK FLUSH
# =========================
def flush_bulk(actions):
    if not actions:
        return
    try:
        helpers.bulk(es, actions, raise_on_error=False, request_timeout=180)
    except Exception as e:
        print(f"⚠️ Bulk insert error: {e}")
    finally:
        actions.clear()


# =========================
# INGEST
# =========================
def ingest():
    ensure_index()

    actions = []
    victim_dirs = find_victim_dirs(LEAK_ROOT)

    print(f"✅ Victim folders found: {len(victim_dirs)}")

    for victim_dir in tqdm(victim_dirs, desc="Ingesting folders"):
        victim_name = os.path.relpath(victim_dir, LEAK_ROOT)

        root_files = find_root_priority_files(victim_dir)

        # --- information.txt (host_info doc)
        info_context = {}
        info_path = root_files.get("information")
        if info_path and os.path.exists(info_path):
            info_context = parse_information_txt(info_path)

            doc = {
                "doc_type": "host_info",
                "timestamp": datetime.now(timezone.utc),
                "victim_folder": victim_name,
                "source_file": os.path.basename(info_path),
                "source_path": victim_dir,
                **info_context
            }

            # stable id -> update on re-run (no duplicates)
            _id = sha1_id("host_info", victim_name, info_path)
            actions.append({"_index": INDEX_NAME, "_id": _id, "_source": doc})

        # --- passwords / unique_passwords (credential docs)
        pw_path = root_files.get("passwords") or root_files.get("unique_passwords")
        if pw_path and os.path.exists(pw_path):
            for cred in parse_passwords_txt(pw_path):
                ip = info_context.get("ip")
                country = info_context.get("country")

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
                    "malware_path": info_context.get("malware_path"),
                    **cred
                }

                # stable id -> same record will overwrite (no duplicates)
                _id = sha1_id(
                    "credential",
                    victim_name,
                    doc.get("host") or "",
                    doc.get("login") or "",
                    doc.get("password") or ""
                )

                actions.append({"_index": INDEX_NAME, "_id": _id, "_source": doc})

        # --- ALWAYS parse autofill (max data)
        autofill_files = find_autofill_files(victim_dir)
        for af_path in autofill_files:
            for item in parse_autofill_txt(af_path):
                doc = {
                    "doc_type": "autofill",
                    "timestamp": datetime.now(timezone.utc),
                    "victim_folder": victim_name,
                    "source_file": os.path.basename(af_path),
                    "source_path": os.path.dirname(af_path),
                    "field": item.get("field"),
                    "value": item.get("value"),
                    "value_keyword": item.get("value_keyword"),
                    "emails": item.get("emails", []),
                    "phones": item.get("phones", []),
                }

                _id = sha1_id(
                    "autofill",
                    victim_name,
                    doc["source_file"],
                    doc.get("field") or "",
                    doc.get("value") or ""
                )
                actions.append({"_index": INDEX_NAME, "_id": _id, "_source": doc})

        if len(actions) >= BULK_SIZE:
            flush_bulk(actions)

    flush_bulk(actions)
    print("✅ Done.")


if __name__ == "__main__":
    ingest()
