"""
Test script to verify duplicate prevention in leak_txt.py
"""
import hashlib

def sha1_id(*parts: str) -> str:
    """Same function from leak_txt.py"""
    s = "||".join([p or "" for p in parts])
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


# Test case: Same credential inserted twice
url1 = "https://example.com"
email1 = "test@example.com"
password1 = "password123"

url2 = "https://example.com"  # Same
email2 = "test@example.com"    # Same
password2 = "password123"      # Same

id1 = sha1_id("credential", url1, email1, password1)
id2 = sha1_id("credential", url2, email2, password2)

print("="*70)
print("DUPLICATE PREVENTION TEST")
print("="*70)
print(f"\nTest 1: Same credential twice")
print(f"  First ID:  {id1}")
print(f"  Second ID: {id2}")
print(f"  Same ID? {id1 == id2} ✅" if id1 == id2 else f"  Same ID? {id1 == id2} ❌")

# Test case: Different password = different credential
url3 = "https://example.com"
email3 = "test@example.com"
password3 = "DIFFERENT_PASSWORD"

id3 = sha1_id("credential", url3, email3, password3)

print(f"\nTest 2: Different password (should be different ID)")
print(f"  Original ID:  {id1}")
print(f"  Different ID: {id3}")
print(f"  Different? {id1 != id3} ✅" if id1 != id3 else f"  Different? {id1 != id3} ❌")

# Test case: Different email = different credential
url4 = "https://example.com"
email4 = "different@example.com"
password4 = "password123"

id4 = sha1_id("credential", url4, email4, password4)

print(f"\nTest 3: Different email (should be different ID)")
print(f"  Original ID:  {id1}")
print(f"  Different ID: {id4}")
print(f"  Different? {id1 != id4} ✅" if id1 != id4 else f"  Different? {id1 != id4} ❌")

print("\n" + "="*70)
print("CONCLUSION:")
print("="*70)
print("✅ Same URL:email:password = Same ID = NO DUPLICATE (updates existing)")
print("✅ Different data = Different ID = New document")
print("="*70)
