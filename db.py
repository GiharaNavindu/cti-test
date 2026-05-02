import psycopg2
from psycopg2.extras import Json  # For JSONB insertion
import os
import gzip
import json

# From pruning (decompress and load lite_bundle)
try:
    with gzip.open("processed_data/lite_bundle.json.gz", "rt", encoding="utf-8") as f:
        serialized = f.read()
    stix_data = json.loads(serialized)  # Parse JSON string
except FileNotFoundError:
    print("Error: processed_data/lite_bundle.json.gz not found. Run prune_stix.py first.")
    exit(1)
except Exception as e:
    print(f"Error reading/parsing bundle: {e}")
    exit(1)

# Extract metadata from bundle
oran_component = "Unknown"
if stix_data.get("objects"):
    for obj in stix_data["objects"]:
        if obj.get("x_oran_component"):
            oran_component = obj["x_oran_component"]
            break

# Use default values; in production, calculate score from relevance metrics
default_priority = 50  # Default priority (0-100)

# DB connection (use env vars for security)
db_pass = os.environ.get("DB_PASS", "postgres")  # Fallback for development only
try:
    conn = psycopg2.connect(
        dbname=os.environ.get("DB_NAME", "cti"),
        user=os.environ.get("DB_USER", "postgres"),  
        password=db_pass,
        host=os.environ.get("DB_HOST", "localhost")
    )
    cur = conn.cursor()

    # Insert pruned data (store parsed JSON as JSONB)
    cur.execute(
        "INSERT INTO threats (stix_json, priority, component) VALUES (%s, %s, %s)",
        (Json(stix_data), default_priority, oran_component)
    )

    conn.commit()
    print(f"Inserted pruned STIX into DB. Component: {oran_component}, Priority: {default_priority}")
except psycopg2.OperationalError as e:
    print(f"Database connection error: {e}")
    exit(1)
except Exception as e:
    print(f"Database insert error: {e}")
    if conn:
        conn.rollback()
finally:
    if cur:
        cur.close()
    if conn:
        conn.close()