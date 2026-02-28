import os
import sys
sys.path.append(os.getcwd())
import requests
import feedparser
import toons
from app.classes import Feed

def debug():
    feeds = Feed.get_all()
    print(f"Found {len(feeds)} configured feeds.")
    for f in feeds:
        print(f" - {f.name}: Enabled={f.enabled}, URL={f.url}")
        if f.enabled:
            try:
                resp = requests.get(f.url, timeout=5)
                print(f"   Response: {resp.status_code}")
                parsed = feedparser.parse(resp.content)
                print(f"   Entries found: {len(parsed.entries)}")
            except Exception as e:
                print(f"   Error: {e}")

if __name__ == "__main__":
    debug()
