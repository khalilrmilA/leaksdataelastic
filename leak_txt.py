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
# Option 1: Single file
INPUT_FILE = None  # Set to a specific file path, or None to use INPUT_FOLDER

# Option 2: Process all .txt files in a folder (excluding _INVALID.txt files)
INPUT_FOLDER = r"C:\Users\khali\Downloads\leaks"  # Folder containing leak files

# Option 3: Pattern matching (e.g., "*.txt" or "@logsredbot*.txt")
FILE_PATTERN = "*.txt"  # Pattern to match files in INPUT_FOLDER

ES_URL = "http://localhost:9200"
INDEX_NAME = "leaks_data"

# Performance settings
BULK_SIZE = 5000  # Increased for better performance
CHUNK_SIZE = 50000  # Process this many lines per thread
MAX_WORKERS = min(16, (os.cpu_count() or 4) * 2)  # More threads for I/O-bound tasks

es = Elasticsearch(ES_URL)
stats_lock = threading.Lock()
print_lock = threading.Lock()
file_lock = threading.Lock()  # Lock for writing to invalid file


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
    Parse line in two formats:
    1. URL:email:pass
    2. email:pass (no URL)
    Returns dict with extracted data or None if invalid.
    """
    line = line.strip()
    if not line:
        return None

    # Find all colons in the line
    parts = line.split(":")

    if len(parts) < 2:  # Changed from 3 to 2 to handle email:pass format
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
    url = ":".join(parts[:email_idx]) if email_idx > 0 else None

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
        "url": url or "",  # Empty string if no URL
        "url_domain": url_domain,
        "email": email.lower(),
        "email_domain": email_domain,
        "password": password,
    }


# =========================
# Processing chunks
# =========================
def process_chunk(lines_chunk, chunk_num, source_file, source_path, invalid_file_path):
    """Process a chunk of lines and return actions for bulk insert."""
    actions = []
    valid = 0
    invalid = 0
    invalid_lines = []

    for line in lines_chunk:
        parsed = parse_leak_line(line)

        if not parsed:
            invalid += 1
            invalid_lines.append(line.rstrip('\n\r'))
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

    # Write invalid lines to file
    if invalid_lines and invalid_file_path:
        write_invalid_lines(invalid_lines, invalid_file_path)

    return actions, valid, invalid, chunk_num


def write_invalid_lines(lines, file_path):
    """Thread-safe writing of invalid lines to output file."""
    with file_lock:
        try:
            with open(file_path, "a", encoding="utf-8", errors="ignore") as f:
                for line in lines:
                    f.write(line + "\n")
        except Exception as e:
            with print_lock:
                print(f"⚠️ Error writing invalid lines: {e}")


# =========================
# File discovery
# =========================
def find_leak_files():
    """Find all leak files to process based on configuration."""
    files_to_process = []

    if INPUT_FILE:
        # Single file mode
        if os.path.exists(INPUT_FILE):
            files_to_process.append(INPUT_FILE)
        else:
            print(f"❌ File not found: {INPUT_FILE}")
    elif INPUT_FOLDER:
        # Folder mode with pattern matching
        if not os.path.exists(INPUT_FOLDER):
            print(f"❌ Folder not found: {INPUT_FOLDER}")
            return []

        import glob
        pattern_path = os.path.join(INPUT_FOLDER, FILE_PATTERN)
        all_files = glob.glob(pattern_path)

        # Filter out _INVALID.txt files
        for f in all_files:
            if not f.endswith("_INVALID.txt"):
                files_to_process.append(f)

        files_to_process.sort()  # Process in alphabetical order

    return files_to_process


# =========================
# Ingest single file
# =========================
def ingest_single_file(input_file):
    """Read a single input file and ingest to Elasticsearch using multi-threading."""

    if not os.path.exists(input_file):
        print(f"❌ File not found: {input_file}")
        return

    # Generate output file path for invalid lines
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    invalid_file_path = os.path.join(
        os.path.dirname(input_file),
        f"{base_name}_INVALID.txt"
    )

    # Clear/create the invalid file
    try:
        with open(invalid_file_path, "w", encoding="utf-8") as f:
            f.write(f"# Invalid lines from: {input_file}\n")
            f.write(f"# Generated: {datetime.now()}\n")
            f.write("#" + "="*70 + "\n\n")
        print(f"📝 Invalid lines will be saved to: {invalid_file_path}\n")
    except Exception as e:
        print(f"⚠️ Could not create invalid file: {e}")
        invalid_file_path = None

    print(f"📄 Processing file: {input_file}")
    print(f"⚙️  Using {MAX_WORKERS} worker threads")
    print(f"📦 Chunk size: {CHUNK_SIZE:,} lines per chunk")
    print(f"📊 Bulk size: {BULK_SIZE:,} documents per batch\n")

    source_file = os.path.basename(input_file)
    source_path = os.path.dirname(input_file)

    total_lines = 0
    total_valid = 0
    total_invalid = 0

    # Reset global stats for this file
    global stats
    stats = {"valid": 0, "invalid": 0, "chunks": 0}

    try:
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
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
                            source_path,
                            invalid_file_path
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
                        source_path,
                        invalid_file_path
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
    if invalid_file_path and total_invalid > 0:
        print(f"📝 Invalid lines saved to: {invalid_file_path}")
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


def ingest_all_files():
    """Main function to process all configured leak files."""

    files = find_leak_files()

    if not files:
        print("❌ No files found to process!")
        print("   Check your configuration:")
        print(f"   - INPUT_FILE: {INPUT_FILE}")
        print(f"   - INPUT_FOLDER: {INPUT_FOLDER}")
        print(f"   - FILE_PATTERN: {FILE_PATTERN}")
        return

    print("="*70)
    print(f"🔍 Found {len(files)} file(s) to process:")
    for i, f in enumerate(files, 1):
        file_size = os.path.getsize(f) / (1024 * 1024)  # MB
        print(f"   {i}. {os.path.basename(f)} ({file_size:.2f} MB)")
    print("="*70 + "\n")

    for i, file_path in enumerate(files, 1):
        print(f"\n{'='*70}")
        print(f"📂 Processing file {i}/{len(files)}")
        print(f"{'='*70}\n")

        ingest_single_file(file_path)

        print(f"\n✅ Completed file {i}/{len(files)}: {os.path.basename(file_path)}\n")

    print("\n" + "="*70)
    print(f"🎉 All {len(files)} file(s) processed successfully!")
    print("="*70)


if __name__ == "__main__":
    ingest_all_files()
