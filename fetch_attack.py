import os
import time
import json
import requests  # For fallback
from taxii2client.v21 import Server, Collection
from datetime import datetime, timedelta
from datetime import UTC  # Python 3.11+; use timezone.utc if older
from requests.exceptions import HTTPError, RequestException

# Configurable options
USE_MATCH_TYPE = True  # Toggle False if issues (filter post-fetch)
RETRIES = 5  # Increased for rate limits
BACKOFF_SEC = 600  # 10 mins to match MITRE's 10 req/10 min limit
FALLBACK_TO_GITHUB = True  # Default True to avoid rate limits during dev
COLLECTION_IDS = {
    "enterprise": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",
    # Add others: "ics": "x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858"
} # collection id dictionary 


# this function implemented to handle issues like rate limits during data fetching
def init_server_with_retry(server_url):
    for attempt in range(RETRIES):
        try:
            server = Server(server_url)
            return server
        except HTTPError as e:
            print(f"HTTP Error on discovery: {e.response.status_code} - {e.response.text}")
            if e.response.status_code == 429:
                print(f"Rate limited on discovery. Retrying in {BACKOFF_SEC} sec...")
                time.sleep(BACKOFF_SEC)
            else:
                raise
        except RequestException as e:
            print(f"Network error on discovery: {e}. Retrying...")
            time.sleep(BACKOFF_SEC * (attempt + 1))
    raise ValueError("Failed to initialize TAXII server after retries.")


# this function is to fetch data from taxii server
# Applied filters are: 1) added_after for last hour, 2) match[type] for attack-pattern and malware 
def fetch_from_taxii():
    server_url = "https://attack-taxii.mitre.org/taxii2/"
    server = init_server_with_retry(server_url) # wrapped in the previous function to avoid rate limit issue

    if not server.api_roots:
        raise ValueError("No API roots found. Check URL/network.")

    for roots in server.api_roots:
        print(f"Available API Root: {roots.title} ({roots.url})")
        

    api_root = server.api_roots[0]
    print(f"Using API Root: {api_root.title} ({api_root.url})")

    collection_id = COLLECTION_IDS["enterprise"]
    collection = next((coll for coll in api_root.collections if coll.id == collection_id), None)
    if not collection:
        raise ValueError(f"Collection {collection_id} not found. Available: {[c.id for c in api_root.collections]}")

    print(f"Using Collection: {collection.title} ({collection.id})")

    # Timestamp: Naive UTC, seconds precision, 'Z' suffix (no offset)
    last_hour = (datetime.now(UTC) - timedelta(hours=1)).replace(tzinfo=None).isoformat(timespec='seconds') + 'Z'
    params = {"added_before": last_hour}
    if USE_MATCH_TYPE:
        params["match[type]"] = "attack-pattern,malware"

    # Headers
    headers = {"Accept": "application/taxii+json;version=2.1"}

    bundle = []
    next_token = None
    for attempt in range(RETRIES):
        try:
            current_params = params.copy()
            if next_token:
                current_params["next"] = next_token

            resp = collection._conn.get(collection.objects_url, headers=headers, params=current_params)
            
            if not isinstance(resp, dict):
                raise ValueError("Unexpected response type from TAXII server.")

            data = resp
            bundle.extend(data.get("objects", []))

            if not data.get("more", False):
                break
            next_token = data.get("next")

        except HTTPError as e:
            print(f"HTTP Error: {e.response.status_code} - {e.response.text}")
            if e.response.status_code == 429:
                print(f"Rate limited. Retrying in {BACKOFF_SEC} sec...")
                time.sleep(BACKOFF_SEC)
            else:
                raise
        except RequestException as e:
            print(f"Network error: {e}. Retrying...")
            time.sleep(BACKOFF_SEC * (attempt + 1))

    return bundle

def fallback_to_github():
    print("Falling back to GitHub JSON download...")
    github_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    for attempt in range(RETRIES):
        try:
            resp = requests.get(github_url)
            resp.raise_for_status()
            data = resp.json()
            return data.get("objects", [])  # Full bundle; filter manually
        except RequestException as e:
            print(f"GitHub fetch error: {e}. Retrying...")
            time.sleep(BACKOFF_SEC * (attempt + 1))
    raise ValueError("GitHub fallback failed after retries.")

def save_bundle_to_file(bundle, output_path="raw_data/attck_bundle.json"):
    """Save bundle to JSON file"""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(bundle, f, indent=4)
    print(f"Saved {len(bundle)} objects to {output_path}")


def get_attack_bundle():
    """Main function: Get ATT&CK bundle with fallback logic"""
    try:
        bundle = fetch_from_taxii()
    except Exception as e:
        print(f"TAXII failed: {e}")
        if FALLBACK_TO_GITHUB:
            bundle = fallback_to_github()
        else:
            raise

    print(f"Fetched {len(bundle)} raw ATT&CK objects.")

    # Post-fetch filter (types if not using match[type], plus keywords)
    interesting_types = ["attack-pattern", "malware", "relationship", "identity", "extension-definition"]
    if not USE_MATCH_TYPE:
        bundle = [obj for obj in bundle if obj.get("type") in interesting_types]

    # Optional: Filter by telecom keywords (comment out if not needed)
    # telecom_keywords = ["5g", "ran", "telecom"]
    # filtered_bundle = [
    #     obj for obj in bundle
    #     if any(kw in obj.get("description", "").lower() for kw in telecom_keywords)
    # ]
    # print(f"Filtered to {len(filtered_bundle)} telecom-relevant objects.")

    return bundle


if __name__ == "__main__":
    bundle = get_attack_bundle()
    save_bundle_to_file(bundle)