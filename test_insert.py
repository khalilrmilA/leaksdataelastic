from elasticsearch import Elasticsearch
from datetime import datetime, timezone

es = Elasticsearch("http://localhost:9200")

doc = {
    "source_file": "test.txt",
    "source_path": "manual_test",
    "login": "admin@example.com",
    "password": "password123",
    "url": "https://example.com/login",
    "domain": "example.com",
    "ip": "8.8.8.8",
    "country": "United States",
    "city": "Mountain View",
    "timestamp": datetime.now(timezone.utc)
}

es.index(index="leaks_data", document=doc)
print("✅ Test document inserted successfully")
