import os

LOCAL_PLATFORM_ID = os.getenv("PLATFORM_ID", "oran-cti-node-alpha")

# Where the new FastAPI RAG Server is running
LOCAL_RAG_KB_URL = os.getenv("LOCAL_RAG_KB_URL", "http://host.docker.internal:8000/api/threats")

# TAXII 2.1 Collection ID for O-RAN Threat Intel
TAXII_COLLECTION_ID = "91a7b528-80eb-42ed-a74d-c6fbd5a26116"

# Registry of peer platforms (Node-Beta)
if LOCAL_PLATFORM_ID == "oran-cti-node-alpha":
    PEER_PLATFORMS = [
        {
            "id": "oran-cti-node-beta",
            "taxii_url": os.getenv(
                "NODE_BETA_TAXII_URL",
                f"http://node-beta:8002/api1/collections/{TAXII_COLLECTION_ID}/objects/",
            ),
            "api_key": "beta-secret-token",
        }
    ]
else:
    PEER_PLATFORMS = []