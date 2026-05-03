import datetime
import asyncio
import os
import uuid
import httpx

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from tenacity import retry, stop_after_attempt, wait_exponential
from .models import STIXIndicator, STIXBundle
from .config import (
    PEER_PLATFORMS,
    LOCAL_PLATFORM_ID,
    LOCAL_RAG_KB_URL,
    TAXII_COLLECTION_ID,
)

app = FastAPI(title="O-RAN TAXII 2.1 Agent (rApp 1)")

# ─── OUTBOUND: Share Local Threats with Peers ─────────────────────────────────

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def _send_to_peer(peer_url: str, bundle_dict: dict):
    """Reliably broadcast STIX bundles to peer networks."""
    async with httpx.AsyncClient() as client:
        response = await client.post(peer_url, json=bundle_dict, timeout=5.0)
        response.raise_for_status()

def _queue_taxii_broadcast(background_tasks: BackgroundTasks, indicator: STIXIndicator):
    """Wrap indicator in a STIX bundle and queue it for peer distribution."""
    bundle = STIXBundle(objects=[indicator])
    bundle_dict = bundle.model_dump()

    for peer in PEER_PLATFORMS:
        print(f"[TAXII OUTBOUND]  Queuing broadcast to {peer['id']}")
        background_tasks.add_task(_send_to_peer, peer["taxii_url"], bundle_dict)

@app.post("/local/share")
async def receive_xapp_escalation(payload: dict, background_tasks: BackgroundTasks):
    """Triggered by xApp 2 when a CRITICAL threat is mitigated locally."""
    print("\n[rApp 1 OUTBOUND] Received Threat Mitigation Event from Near-RT RIC")

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ue_id = payload.get("ue_id", "unknown-ue")
    attack_type = payload.get("attack_type", "AI-Verified Traffic Spike")
    description = payload.get("description", "Blocked high-throughput anomaly")

    # Construct the formal STIX Indicator
    stix_indicator = STIXIndicator(
        id=f"indicator--{uuid.uuid4()}",
        created=now,
        modified=now,
        name=f"O-RAN Threat: {attack_type}",
        description=description,
        indicator_types=["malicious-activity"],
        pattern=f"[network-traffic:dst_ref.value = '{ue_id}']",
        pattern_type="stix",
        valid_from=now
    )

    _queue_taxii_broadcast(background_tasks, stix_indicator)

    return {
        "status": "sharing_initiated",
        "taxii_bundles_generated": 1,
    }


# ─── INBOUND: Receive Threats from Peers & Update RAG ─────────────────────────

@app.post("/api1/collections/{collection_id}/objects/")
async def receive_peer_taxii(
    collection_id: str, 
    bundle: STIXBundle, 
    authorization: str = Header(None)
):
    """Receive STIX bundles from Node-Beta and push into the local RAG DB."""
    if collection_id != TAXII_COLLECTION_ID:
        raise HTTPException(status_code=404, detail="Collection not found")

    print(f"\n[rApp 1 INBOUND] Received TAXII STIX Bundle from Peer Network!")

    # Extract indicator logic from the STIX bundle
    for obj in bundle.objects:
        if obj.type == "indicator":
            
            # Format the data for our local RAG Knowledge Base (api_server.py)
            rag_kb_entry = {
                "threat_id": obj.id,
                "threat_name": obj.name,
                "threat_description": obj.description,
                "threat_type": "peer-shared-indicator",
                "affected_components": ["O-DU", "O-CU"],
                "mitigations": [{"mitigation_name": "E2SM-RC PRB Limit", "description": "Throttle UE"}]
            }

            # Push directly into the RAG ChromaDB so xApp 1 can pull it
            try:
                resp = httpx.post(LOCAL_RAG_KB_URL, json=rag_kb_entry, timeout=3.0)
                if resp.status_code in [200, 201]:
                    print(f"[rApp 1 INBOUND] Successfully ingested peer threat into local RAG DB!")
            except Exception as e:
                print(f"[rApp 1 INBOUND] Failed to update RAG DB: {e}")

    return {"status": "Accepted", "parsed_objects": len(bundle.objects)}