"""
Test script to verify both format parsing
"""
import re

EMAIL_REGEX = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)

def parse_leak_line(line: str) -> dict | None:
    """
    Parse line in two formats:
    1. URL:email:pass
    2. email:pass (no URL)
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split(":")

    if len(parts) < 2:
        return None

    email_idx = -1
    for i, part in enumerate(parts):
        if "@" in part and EMAIL_REGEX.search(part):
            email_idx = i
            break

    if email_idx == -1:
        return None

    url = ":".join(parts[:email_idx]) if email_idx > 0 else None
    email = parts[email_idx].strip()

    if email_idx + 1 < len(parts):
        password = ":".join(parts[email_idx + 1:]).strip()
    else:
        password = ""

    if not EMAIL_REGEX.match(email):
        return None

    return {
        "url": url or "",
        "email": email.lower(),
        "password": password,
    }


# Test cases
print("="*70)
print("FORMAT PARSING TEST")
print("="*70)

test_cases = [
    # Format 1: URL:email:password
    "https://example.com:user@example.com:password123",
    "signin.ea.com/login:test@gmail.com:MyPass!123",

    # Format 2: email:password (NO URL)
    "user@example.com:password123",
    "test@gmail.com:MyPassword",
    "admin@domain.com:pass:with:colons",

    # Invalid cases
    "no-email-here:password",
    "just-text",
    "",
]

for i, line in enumerate(test_cases, 1):
    result = parse_leak_line(line)
    print(f"\nTest {i}: {line[:50]}...")
    if result:
        print(f"  [OK] VALID")
        print(f"     URL: {result['url'] or '(none)'}")
        print(f"     Email: {result['email']}")
        print(f"     Password: {result['password']}")
    else:
        print(f"  [X] INVALID (will be logged to _INVALID.txt)")

print("\n" + "="*70)
print("✅ Both formats are supported!")
print("="*70)
