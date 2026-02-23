import os
import re
import time
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import tldextract
from elasticsearch import Elasticsearch, helpers, NotFoundError


# =========================
# CONFIG (EDIT THESE)
# =========================
# Option 1: Single file
INPUT_FILE = None  # Set to a specific file path, or None to use INPUT_FOLDER

# Option 2: Process all .txt files in a folder (excluding _INVALID.txt files)
INPUT_FOLDER = r"/home/sysadmin/Downloads"  # Folder containing leak files

# Option 3: Pattern matching (e.g., "*.txt" or "@logsredbot*.txt")
FILE_PATTERN = "*.txt"  # Pattern to match files in INPUT_FOLDER

ES_URL = "http://localhost:9200"
INDEX_NAME = "leaks_data"

# Performance settings
BULK_SIZE = 5000          # Documents per bulk request
CHUNK_SIZE = 50000        # Lines per thread chunk
MAX_WORKERS = min(16, (os.cpu_count() or 4) * 2)
MAX_BULK_RETRIES = 3      # How many times to retry a failed bulk batch
RETRY_BACKOFF = 2         # Base seconds for exponential backoff

es = Elasticsearch(ES_URL)
stats_lock = threading.Lock()
print_lock = threading.Lock()
file_lock = threading.Lock()


# =========================
# REGEX
# =========================
EMAIL_REGEX = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


# =========================
# Error categories
# =========================
ERROR_DUPLICATE = "duplicate"
ERROR_TRANSIENT  = "transient"   # 429 / 503 / timeout  → retry
ERROR_PERMANENT  = "permanent"   # anything else        → individual fallback


# =========================
# Global stats
# =========================
stats = {
    "valid":      0,
    "invalid":    0,
    "chunks":     0,
    "inserted":   0,   # successfully written to ES
    "duplicates": 0,   # skipped because already existed (409)
    "retried":    0,   # documents that needed a retry
    "es_errors":  0,   # documents that failed after all retries
}


# =========================
# Helpers
# =========================
def sha1_id(*parts: str) -> str:
    """Generate a stable unique ID from its component parts."""
    s = "||".join([p or "" for p in parts])
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


def extract_domain_from_email(email: str) -> str | None:
    if not email or "@" not in email:
        return None
    try:
        domain_part = email.split("@")[1]
        ext = tldextract.extract(domain_part)
        return ext.registered_domain or domain_part
    except Exception:
        return None


def safe_domain(host_or_url: str | None) -> str | None:
    if not host_or_url:
        return None
    try:
        if host_or_url.startswith("android://"):
            return "android-app"
        u = urlparse(host_or_url)
        if u.scheme and u.netloc:
            ext = tldextract.extract(u.netloc)
            return ext.registered_domain or u.netloc
        ext = tldextract.extract(host_or_url)
        return ext.registered_domain or host_or_url
    except Exception:
        return None


# =========================
# ES connection check
# =========================
def check_es_connection() -> bool:
    """Verify that Elasticsearch is reachable before processing."""
    try:
        info = es.info()
        version = info.get("version", {}).get("number", "unknown")
        print(f"Connected to Elasticsearch {version} at {ES_URL}")
        return True
    except Exception as e:
        print(f"Cannot reach Elasticsearch at {ES_URL}: {e}")
        return False


# =========================
# Parsing
# =========================
def parse_leak_line(line: str) -> dict | None:
    """
    Parse line in two formats:
      1. URL:email:pass
      2. email:pass  (no URL)
    Returns a dict with extracted fields, or None if unparseable.
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split(":")
    if len(parts) < 2:
        return None

    # Locate the email token (contains '@')
    email_idx = -1
    for i, part in enumerate(parts):
        if "@" in part and EMAIL_REGEX.search(part):
            email_idx = i
            break

    if email_idx == -1:
        return None

    url      = ":".join(parts[:email_idx]) if email_idx > 0 else None
    email    = parts[email_idx].strip()
    password = ":".join(parts[email_idx + 1:]).strip() if email_idx + 1 < len(parts) else ""

    if not EMAIL_REGEX.match(email):
        return None

    return {
        "url":          url or "",
        "url_domain":   safe_domain(url) if url else None,
        "email":        email.lower(),
        "email_domain": extract_domain_from_email(email),
        "password":     password,
    }


# =========================
# Processing chunks
# =========================
def process_chunk(lines_chunk, chunk_num, source_file, source_path, invalid_file_path):
    """Parse a chunk of raw lines and return Elasticsearch bulk actions."""
    actions      = []
    valid        = 0
    invalid      = 0
    invalid_lines = []

    for line in lines_chunk:
        parsed = parse_leak_line(line)

        if not parsed:
            invalid += 1
            invalid_lines.append(line.rstrip('\n\r'))
            continue

        valid += 1

        doc = {
            "doc_type":        "credential",
            "timestamp":       datetime.now(timezone.utc),
            "source_file":     source_file,
            "source_path":     source_path,
            "url":             parsed["url"],
            "url_domain":      parsed["url_domain"],
            "host":            parsed["url"],
            "domain":          parsed["email_domain"],
            "login":           parsed["email"],
            "emails":          [parsed["email"]],
            "password":        parsed["password"],
            "password_is_json": False,
        }

        _id = sha1_id("credential", doc["url"], doc["login"], doc["password"])

        actions.append({
            "_index":    INDEX_NAME,
            "_id":       _id,
            "_op_type":  "create",   # Skip (count as duplicate) if already exists
            "_source":   doc,
        })

    if invalid_lines and invalid_file_path:
        write_invalid_lines(invalid_lines, invalid_file_path)

    return actions, valid, invalid, chunk_num


def write_invalid_lines(lines, file_path):
    """Thread-safe append of unparseable lines to the invalid output file."""
    with file_lock:
        try:
            with open(file_path, "a", encoding="utf-8", errors="ignore") as f:
                for line in lines:
                    f.write(line + "\n")
        except Exception as e:
            with print_lock:
                print(f"Warning: error writing invalid lines: {e}")


# =========================
# Error classification
# =========================
def classify_bulk_error(err: dict) -> tuple[str, str]:
    """
    Classify a single error returned by helpers.bulk.

    Returns (error_category, document_id).
    Categories: ERROR_DUPLICATE | ERROR_TRANSIENT | ERROR_PERMANENT
    """
    op_name  = list(err.keys())[0]          # "create", "index", "update", …
    op       = err[op_name]
    status   = op.get("status", 0)
    err_info = op.get("error", {})
    err_type = err_info.get("type", "") if isinstance(err_info, dict) else ""
    doc_id   = op.get("_id", "")

    if status == 409 or "conflict" in err_type:
        return ERROR_DUPLICATE, doc_id

    if status in (429, 503) or "timeout" in str(err_info).lower():
        return ERROR_TRANSIENT, doc_id

    return ERROR_PERMANENT, doc_id


# =========================
# Individual insert fallback
# =========================
def insert_individually(actions: list) -> tuple[int, int]:
    """
    Last-resort fallback: insert documents one at a time.
    Returns (success_count, error_count).
    """
    success = 0
    errors  = 0

    for action in actions:
        try:
            es.index(
                index=action["_index"],
                id=action["_id"],
                document=action["_source"],
                op_type="create",          # still honour create semantics
                request_timeout=30,
            )
            success += 1
        except Exception as e:
            err_str = str(e)
            # 409 means the document already exists – that is acceptable
            if "409" in err_str or "conflict" in err_str.lower():
                with stats_lock:
                    stats["duplicates"] += 1
                success += 1
            else:
                errors += 1
                with print_lock:
                    print(f"  Individual insert failed [{action['_id'][:8]}…]: {e}")

    return success, errors


# =========================
# Bulk flush with retry + fallback
# =========================
def flush_bulk_with_retry(actions: list) -> tuple[int, int, int]:
    """
    Send a list of bulk actions to Elasticsearch.

    Retry logic:
      - Transient errors (429 / 503 / timeout) → exponential backoff retry
      - Permanent errors                        → individual insert fallback
      - Duplicate (409)                         → counted, not retried

    Returns (inserted, duplicates, es_errors).
    """
    if not actions:
        return 0, 0, 0

    # Build an id→action map for efficient lookup during retry
    action_map: dict[str, dict] = {a["_id"]: a for a in actions}

    pending    = list(actions)
    inserted   = 0
    duplicates = 0
    es_errors  = 0

    for attempt in range(1, MAX_BULK_RETRIES + 1):
        if not pending:
            break

        try:
            ok_count, errors = helpers.bulk(
                es,
                pending,
                chunk_size=BULK_SIZE,
                max_chunk_bytes=10 * 1024 * 1024,  # 10 MB
                raise_on_error=False,
                request_timeout=300,
            )
            inserted += ok_count

        except Exception as e:
            # The whole request failed (connection error, etc.)
            with print_lock:
                print(f"  Bulk request error (attempt {attempt}/{MAX_BULK_RETRIES}): {e}")
            errors = []   # errors list unknown – treat all pending as transient

            if attempt < MAX_BULK_RETRIES:
                wait = RETRY_BACKOFF ** attempt
                with print_lock:
                    print(f"  Waiting {wait}s before retry…")
                time.sleep(wait)
                with stats_lock:
                    stats["retried"] += len(pending)
                continue
            else:
                # All retries exhausted – fall back to individual inserts
                with print_lock:
                    print(f"  Falling back to individual inserts for {len(pending)} docs…")
                ind_ok, ind_err = insert_individually(pending)
                inserted  += ind_ok
                es_errors += ind_err
                pending    = []
                break

        # ── Classify each error ──────────────────────────────────────────────
        retry_ids    = []
        perm_ids     = []

        for err in errors:
            category, doc_id = classify_bulk_error(err)

            if category == ERROR_DUPLICATE:
                duplicates += 1

            elif category == ERROR_TRANSIENT:
                retry_ids.append(doc_id)

            else:  # ERROR_PERMANENT
                perm_ids.append(doc_id)

        # Permanently-failed docs → individual insert (one last chance)
        if perm_ids:
            perm_actions = [action_map[did] for did in perm_ids if did in action_map]
            with print_lock:
                print(f"  {len(perm_actions)} permanent error(s) on attempt {attempt} – trying individual insert…")
            ind_ok, ind_err = insert_individually(perm_actions)
            inserted  += ind_ok
            es_errors += ind_err

        # Transient → schedule for retry
        if retry_ids and attempt < MAX_BULK_RETRIES:
            pending = [action_map[did] for did in retry_ids if did in action_map]
            wait    = RETRY_BACKOFF ** attempt
            with print_lock:
                print(f"  Retrying {len(pending)} transient error(s) in {wait}s (attempt {attempt}/{MAX_BULK_RETRIES})…")
            time.sleep(wait)
            with stats_lock:
                stats["retried"] += len(pending)
        elif retry_ids:
            # Last attempt reached for transient errors → individual fallback
            transient_actions = [action_map[did] for did in retry_ids if did in action_map]
            with print_lock:
                print(f"  {len(transient_actions)} transient error(s) still failing – individual insert fallback…")
            ind_ok, ind_err = insert_individually(transient_actions)
            inserted  += ind_ok
            es_errors += ind_err
            pending    = []
        else:
            pending = []

    return inserted, duplicates, es_errors


# =========================
# File discovery
# =========================
def find_leak_files() -> list[str]:
    """Return all leak files to process based on configuration."""
    files_to_process = []

    if INPUT_FILE:
        if os.path.exists(INPUT_FILE):
            files_to_process.append(INPUT_FILE)
        else:
            print(f"File not found: {INPUT_FILE}")
    elif INPUT_FOLDER:
        if not os.path.exists(INPUT_FOLDER):
            print(f"Folder not found: {INPUT_FOLDER}")
            return []

        import glob
        all_files = glob.glob(os.path.join(INPUT_FOLDER, FILE_PATTERN))
        files_to_process = sorted(f for f in all_files if not f.endswith("_INVALID.txt"))

    return files_to_process


# =========================
# Future processing
# =========================
def process_completed_futures(futures: list, final: bool = False):
    """Drain completed futures, bulk-flush to ES, and update global stats."""
    global stats

    actions_buffer = []
    completed      = []

    for future in as_completed(futures):
        try:
            actions, valid, invalid, chunk_num = future.result()

            with stats_lock:
                stats["valid"]   += valid
                stats["invalid"] += invalid
                stats["chunks"]  += 1

            actions_buffer.extend(actions)
            completed.append(future)

            if len(actions_buffer) >= BULK_SIZE:
                inserted, dupes, errs = flush_bulk_with_retry(actions_buffer)
                actions_buffer = []
                with stats_lock:
                    stats["inserted"]   += inserted
                    stats["duplicates"] += dupes
                    stats["es_errors"]  += errs
                with print_lock:
                    print(
                        f"Chunk #{chunk_num:>4} | "
                        f"valid {stats['valid']:,} | "
                        f"inserted {stats['inserted']:,} | "
                        f"dupes {stats['duplicates']:,} | "
                        f"errors {stats['es_errors']:,}"
                    )

        except Exception as e:
            with print_lock:
                print(f"Warning: error processing chunk: {e}")
            completed.append(future)

    for f in completed:
        futures.remove(f)

    # Final flush for whatever remains in the buffer
    if actions_buffer:
        inserted, dupes, errs = flush_bulk_with_retry(actions_buffer)
        with stats_lock:
            stats["inserted"]   += inserted
            stats["duplicates"] += dupes
            stats["es_errors"]  += errs
        if final:
            with print_lock:
                print(
                    f"Final flush | "
                    f"inserted {stats['inserted']:,} | "
                    f"dupes {stats['duplicates']:,} | "
                    f"errors {stats['es_errors']:,}"
                )


# =========================
# Ingest single file
# =========================
def ingest_single_file(input_file: str):
    """Read one file and ingest its contents into Elasticsearch."""

    if not os.path.exists(input_file):
        print(f"File not found: {input_file}")
        return

    base_name         = os.path.splitext(os.path.basename(input_file))[0]
    invalid_file_path = os.path.join(os.path.dirname(input_file), f"{base_name}_INVALID.txt")

    try:
        with open(invalid_file_path, "w", encoding="utf-8") as f:
            f.write(f"# Invalid lines from: {input_file}\n")
            f.write(f"# Generated: {datetime.now()}\n")
            f.write("#" + "=" * 70 + "\n\n")
        print(f"Invalid lines will be saved to: {invalid_file_path}\n")
    except Exception as e:
        print(f"Warning: could not create invalid file: {e}")
        invalid_file_path = None

    print(f"Processing file : {input_file}")
    print(f"Worker threads  : {MAX_WORKERS}")
    print(f"Chunk size      : {CHUNK_SIZE:,} lines")
    print(f"Bulk size       : {BULK_SIZE:,} documents\n")

    source_file = os.path.basename(input_file)
    source_path = os.path.dirname(input_file)
    total_lines = 0

    # Reset stats for this file
    global stats
    stats = {k: 0 for k in stats}

    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures   = []
                chunk     = []
                chunk_num = 0

                for line in f:
                    total_lines += 1
                    chunk.append(line)

                    if len(chunk) >= CHUNK_SIZE:
                        chunk_num += 1
                        futures.append(
                            executor.submit(
                                process_chunk, chunk, chunk_num,
                                source_file, source_path, invalid_file_path
                            )
                        )
                        chunk = []

                        if len(futures) >= MAX_WORKERS * 2:
                            process_completed_futures(futures)

                if chunk:
                    chunk_num += 1
                    futures.append(
                        executor.submit(
                            process_chunk, chunk, chunk_num,
                            source_file, source_path, invalid_file_path
                        )
                    )

                process_completed_futures(futures, final=True)

    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # ── Final report ──────────────────────────────────────────────────────────
    total_valid   = stats["valid"]
    total_invalid = stats["invalid"]
    success_rate  = (total_valid / total_lines * 100) if total_lines else 0.0

    print()
    print("=" * 60)
    print("Processing complete!")
    print("-" * 60)
    print(f"  Total lines read  : {total_lines:,}")
    print(f"  Parseable lines   : {total_valid:,}")
    print(f"  Unparseable lines : {total_invalid:,}")
    print(f"  Parse success rate: {success_rate:.2f}%")
    print("-" * 60)
    print(f"  Inserted (new)    : {stats['inserted']:,}")
    print(f"  Skipped (dupes)   : {stats['duplicates']:,}")
    print(f"  Retried docs      : {stats['retried']:,}")
    print(f"  Failed (errors)   : {stats['es_errors']:,}")
    print("=" * 60)
    if invalid_file_path and total_invalid > 0:
        print(f"  Invalid lines     : {invalid_file_path}")
    print()


# =========================
# Ingest all files
# =========================
def ingest_all_files():
    """Main entry point: verify ES, discover files, ingest each one."""

    if not check_es_connection():
        print("Aborting – Elasticsearch is not reachable.")
        return

    files = find_leak_files()

    if not files:
        print("No files found to process!")
        print(f"  INPUT_FILE   : {INPUT_FILE}")
        print(f"  INPUT_FOLDER : {INPUT_FOLDER}")
        print(f"  FILE_PATTERN : {FILE_PATTERN}")
        return

    print("=" * 70)
    print(f"Found {len(files)} file(s) to process:")
    for i, f in enumerate(files, 1):
        size_mb = os.path.getsize(f) / (1024 * 1024)
        print(f"  {i}. {os.path.basename(f)} ({size_mb:.2f} MB)")
    print("=" * 70 + "\n")

    for i, file_path in enumerate(files, 1):
        print(f"\n{'=' * 70}")
        print(f"File {i}/{len(files)}: {os.path.basename(file_path)}")
        print(f"{'=' * 70}\n")
        ingest_single_file(file_path)
        print(f"Completed file {i}/{len(files)}: {os.path.basename(file_path)}\n")

    print("=" * 70)
    print(f"All {len(files)} file(s) processed.")
    print("=" * 70)


if __name__ == "__main__":
    ingest_all_files()
