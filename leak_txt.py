import os
import re
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import tldextract
from elasticsearch import Elasticsearch, helpers


# =========================
# CONFIG (EDIT THESE)
# =========================
INPUT_FILE = r"C:\Users\khali\Downloads\leaks\@logsredbot [5.2M] #3933.txt"  # Change this to your file path
ES_URL = "http://localhost:9200"
INDEX_NAME = "leaks_data"

# Performance settings
BULK_SIZE = 5000  # Increased for better performance
CHUNK_SIZE = 50000  # Process this many lines per thread
MAX_WORKERS = min(16, (os.cpu_count() or 4) * 2)  # More threads for I/O-bound tasks

es = Elasticsearch(ES_URL)
stats_lock = threading.Lock()
print_lock = threading.Lock()


# =========================
# REGEX
# =========================
EMAIL_REGEX = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


# =========================
# Helpers
# =========================
def sha1_id(*parts: str) -> str:
    """Generate unique ID from parts."""
    s = "||".join([p or "" for p in parts])
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


def extract_domain_from_email(email: str) -> str | None:
    """Extract domain from email address (e.g., user@example.com -> example.com)."""
    if not email or "@" not in email:
        return None

    try:
        domain_part = email.split("@")[1]
        ext = tldextract.extract(domain_part)
        return ext.registered_domain or domain_part
    except Exception:
        return None


def safe_domain(host_or_url: str | None) -> str | None:
    """Extract clean domain from URL or host."""
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


# =========================
# Parsing
# =========================
def parse_leak_line(line: str) -> dict | None:
    """
    Parse line in format: URL:email:pass
    Returns dict with extracted data or None if invalid.
    """
    line = line.strip()
    if not line:
        return None

    # Find all colons in the line
    parts = line.split(":")

    if len(parts) < 3:
        return None

    # Strategy: Find the email in the parts (it will have @)
    # Everything before email is URL, everything after is password
    email_idx = -1
    for i, part in enumerate(parts):
        if "@" in part and EMAIL_REGEX.search(part):
            email_idx = i
            break

    if email_idx == -1:
        return None

    # Reconstruct URL (everything before email)
    url = ":".join(parts[:email_idx])

    # Email is at email_idx
    email = parts[email_idx].strip()

    # Password is everything after email (might contain colons)
    if email_idx + 1 < len(parts):
        password = ":".join(parts[email_idx + 1:]).strip()
    else:
        password = ""

    # Validate email format more strictly
    if not EMAIL_REGEX.match(email):
        return None

    # Extract domain from email
    email_domain = extract_domain_from_email(email)

    # Extract domain from URL (if it's a valid URL)
    url_domain = safe_domain(url) if url else None

    return {
        "url": url,
        "url_domain": url_domain,
        "email": email.lower(),
        "email_domain": email_domain,
        "password": password,
    }


# =========================
# Processing chunks
# =========================
def process_chunk(lines_chunk, chunk_num, source_file, source_path):
    """Process a chunk of lines and return actions for bulk insert."""
    actions = []
    valid = 0
    invalid = 0

    for line in lines_chunk:
        parsed = parse_leak_line(line)

        if not parsed:
            invalid += 1
            continue

        valid += 1

        # Create Elasticsearch document
        doc = {
            "doc_type": "credential",
            "timestamp": datetime.now(timezone.utc),
            "source_file": source_file,
            "source_path": source_path,
            "url": parsed["url"],
            "url_domain": parsed["url_domain"],
            "host": parsed["url"],
            "domain": parsed["email_domain"],
            "login": parsed["email"],
            "emails": [parsed["email"]],
            "password": parsed["password"],
            "password_is_json": False,
        }

        # Generate unique ID
        _id = sha1_id(
            "credential",
            doc["url"],
            doc["login"],
            doc["password"],
        )

        actions.append({
            "_index": INDEX_NAME,
            "_id": _id,
            "_source": doc
        })

    return actions, valid, invalid, chunk_num


# =========================
# Ingest
# =========================
def ingest_file():
    """Read the input file and ingest to Elasticsearch using multi-threading."""

    if not os.path.exists(INPUT_FILE):
        print(f"❌ File not found: {INPUT_FILE}")
        return

    print(f"📄 Processing file: {INPUT_FILE}")
    print(f"⚙️  Using {MAX_WORKERS} worker threads")
    print(f"📦 Chunk size: {CHUNK_SIZE:,} lines per chunk")
    print(f"📊 Bulk size: {BULK_SIZE:,} documents per batch\n")

    source_file = os.path.basename(INPUT_FILE)
    source_path = os.path.dirname(INPUT_FILE)

    total_lines = 0
    total_valid = 0
    total_invalid = 0

    try:
        with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = []
                chunk = []
                chunk_num = 0

                for line in f:
                    total_lines += 1
                    chunk.append(line)

                    # When chunk is full, submit it to thread pool
                    if len(chunk) >= CHUNK_SIZE:
                        chunk_num += 1
                        future = executor.submit(
                            process_chunk,
                            chunk,
                            chunk_num,
                            source_file,
                            source_path
                        )
                        futures.append(future)
                        chunk = []

                        # Process completed futures to avoid memory buildup
                        if len(futures) >= MAX_WORKERS * 2:
                            process_completed_futures(futures)

                # Submit remaining chunk
                if chunk:
                    chunk_num += 1
                    future = executor.submit(
                        process_chunk,
                        chunk,
                        chunk_num,
                        source_file,
                        source_path
                    )
                    futures.append(future)

                # Process all remaining futures
                process_completed_futures(futures, final=True)

        # Get final stats
        total_valid = stats["valid"]
        total_invalid = stats["invalid"]

    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return

    print(f"\n" + "="*50)
    print(f"✅ Processing complete!")
    print(f"📊 Total lines: {total_lines:,}")
    print(f"✅ Valid entries: {total_valid:,}")
    print(f"❌ Invalid/skipped: {total_invalid:,}")
    print(f"📈 Success rate: {(total_valid/total_lines*100):.2f}%")
    print("="*50)


# Global stats
stats = {"valid": 0, "invalid": 0, "chunks": 0}


def process_completed_futures(futures, final=False):
    """Process completed futures and flush to Elasticsearch."""
    global stats

    actions_buffer = []
    completed = []

    for future in as_completed(futures):
        try:
            actions, valid, invalid, chunk_num = future.result()

            with stats_lock:
                stats["valid"] += valid
                stats["invalid"] += invalid
                stats["chunks"] += 1

            actions_buffer.extend(actions)
            completed.append(future)

            # Flush when buffer is large enough
            if len(actions_buffer) >= BULK_SIZE:
                flush_bulk(actions_buffer)
                with print_lock:
                    print(f"✅ Chunk #{chunk_num} | Total processed: {stats['valid']:,} valid, {stats['invalid']:,} invalid")

        except Exception as e:
            with print_lock:
                print(f"⚠️ Error processing chunk: {e}")
            completed.append(future)

    # Remove completed futures
    for f in completed:
        futures.remove(f)

    # Flush remaining actions
    if actions_buffer:
        flush_bulk(actions_buffer)
        if final:
            with print_lock:
                print(f"✅ Final flush | Total: {stats['valid']:,} valid entries")


def flush_bulk(actions):
    """Flush bulk actions to Elasticsearch with optimized settings."""
    if not actions:
        return

    try:
        helpers.bulk(
            es,
            actions,
            chunk_size=BULK_SIZE,
            max_chunk_bytes=10485760,  # 10MB
            raise_on_error=False,
            request_timeout=300,
            max_retries=3,
            initial_backoff=2
        )
    except Exception as e:
        with print_lock:
            print(f"⚠️ Bulk insert error: {e}")
    finally:
        actions.clear()


if __name__ == "__main__":
    ingest_file()
