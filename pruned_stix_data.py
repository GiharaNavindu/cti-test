"""
pruned_stix_data.py

End-to-end pipeline:
1) Fetch MITRE ATT&CK STIX objects via TAXII 2.1 (Enterprise + ICS if available)
2) Build mitigation links (course-of-action --mitigates--> attack-pattern)
3) Prune to O-RAN ecosystem relevance using embeddings + your expanded ontology
4) Map each kept technique to meaningful O-RAN ecosystem buckets:
   - O-Cloud, SMO, Near-RT RIC, Non-RT RIC, IAM, CI/CD, Interfaces, O-RU/O-DU/O-CU, RAN-General
5) Export knowledge graph files:
   - oran_outputs/oran_pruned_nodes.json
   - oran_outputs/oran_pruned_edges.json

Requirements (inside your venv):
  pip install taxii2-client sentence-transformers numpy

Run:
  python pipeline/pruned_stix_data.py
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple, Set, Optional

import numpy as np
from sentence_transformers import SentenceTransformer

from taxii2client.v21 import Server  # TAXII 2.1 client


# ------------------------
# Config
# ------------------------

# TAXII discovery endpoint (MITRE ATT&CK)
# NOTE: Some environments are picky about trailing slash; this one usually works:
TAXII_SERVER = "https://attack-taxii.mitre.org/taxii2/"

# Local ontology file (Windows path example)
# Update if your file is elsewhere:
ORAN_ONTOLOGY_PATH = Path(r"E:\FYP\stixx-cti\pipeline\oran_ontology.json")

OUT_DIR = Path("oran_outputs")
OUT_DIR.mkdir(exist_ok=True)

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

# Lower threshold for broader O-RAN ecosystem coverage
RELEVANCE_THRESHOLD = 0.30

# Connect each technique to top-K matched ontology terms (buckets)
TOP_K_COMPONENTS = 3

# Keep description size bounded in JSON outputs
MAX_DESC_CHARS = 5000


# Buckets you want in the graph (you can extend)
BUCKETS = [
    "O-Cloud",
    "SMO",
    "Near-RT RIC",
    "Non-RT RIC",
    "O-RU",
    "O-DU",
    "O-CU",
    "Interfaces",
    "CI/CD",
    "IAM",
    "RAN-General",
]


# ------------------------
# Helpers
# ------------------------

def load_json(p: Path) -> Any:
    if not p.exists():
        raise FileNotFoundError(f"Ontology file not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def stix_text(obj: Dict[str, Any]) -> str:
    name = obj.get("name", "") or ""
    desc = obj.get("description", "") or ""
    return (name + "\n" + desc).strip()


def get_external_id(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def cosine_topk(q: np.ndarray, M: np.ndarray, k: int) -> List[Tuple[int, float]]:
    sims = M @ q  # embeddings normalized => cosine similarity
    idx = np.argsort(-sims)[:k]
    return [(int(i), float(sims[i])) for i in idx]


def is_deprecated(ap: Dict[str, Any]) -> bool:
    # ATT&CK sometimes embeds deprecation note in description
    d = (ap.get("description") or "").lower()
    return "deprecated" in d


# ------------------------
# TAXII fetch
# ------------------------

def fetch_attack_objects() -> List[Dict[str, Any]]:
    """
    Fetch STIX objects from MITRE ATT&CK TAXII.
    - Discovers API roots
    - Selects Enterprise + ICS collections by title when available
    - Downloads objects from those collections
    """
    try:
        server = Server(TAXII_SERVER)
    except Exception as e:
        raise RuntimeError(f"Failed to initialize TAXII Server at {TAXII_SERVER}: {e}")

    # Load discovery (api_roots)
    try:
        api_roots = server.api_roots
    except Exception as e:
        raise RuntimeError(f"Failed to load TAXII discovery from {TAXII_SERVER}: {e}")

    if not api_roots:
        raise RuntimeError("No API roots found from TAXII discovery. Check TAXII_SERVER URL.")

    # MITRE usually has one root; pick the first
    api_root = api_roots[0]

    # Load collections
    try:
        api_root.refresh_collections()
    except Exception:
        # Some client versions load automatically; ignore refresh failures and try reading
        pass

    collections = getattr(api_root, "collections", None) or []
    if not collections:
        raise RuntimeError("No collections found in TAXII API root.")

    # Choose enterprise + ics by title (fallback to all if not found)
    chosen = []
    for c in collections:
        title = (c.title or "").lower()
        if ("enterprise" in title) or ("ics" in title):
            chosen.append(c)

    if not chosen:
        print("WARNING: Could not find Enterprise/ICS collections by title. Using all collections.")
        chosen = collections

    all_objs: List[Dict[str, Any]] = []
    for col in chosen:
        try:
            bundle = col.get_objects()
            objs = bundle.get("objects", []) if isinstance(bundle, dict) else []
            print(f"Fetched {len(objs)} objects from: {col.title}")
            all_objs.extend(objs)
        except Exception as e:
            print(f"WARNING: Failed to fetch objects from collection '{col.title}': {e}")

    # Deduplicate by (id, modified) when possible; else by id
    seen = set()
    deduped = []
    for o in all_objs:
        if not isinstance(o, dict) or "id" not in o:
            continue
        key = (o.get("id"), o.get("modified") or o.get("created"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(o)

    print(f"Total unique objects fetched: {len(deduped)}")
    return deduped


# ------------------------
# Build mitigation map (attack-pattern -> course-of-action)
# ------------------------

def build_mitigation_map(objects: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Returns: attack_pattern_id -> list of course-of-action objects
    Uses relationships:
      relationship_type = "mitigates"
      source_ref = course-of-action
      target_ref = attack-pattern
    """
    by_id = {o["id"]: o for o in objects if isinstance(o, dict) and "id" in o}
    out: Dict[str, List[Dict[str, Any]]] = {}

    for o in objects:
        if not isinstance(o, dict):
            continue
        if o.get("type") != "relationship":
            continue
        if o.get("relationship_type") != "mitigates":
            continue

        src = o.get("source_ref")
        tgt = o.get("target_ref")
        if not src or not tgt:
            continue

        src_obj = by_id.get(src)
        tgt_obj = by_id.get(tgt)
        if not src_obj or not tgt_obj:
            continue

        if src_obj.get("type") != "course-of-action":
            continue
        if tgt_obj.get("type") != "attack-pattern":
            continue

        out.setdefault(tgt, []).append(src_obj)

    return out


# ------------------------
# O-RAN relevance + bucket mapping
# ------------------------

def build_oran_terms(ontology: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Returns:
      - components list (from ontology["components"])
      - terms list (components + interfaces + keywords; deduped)
    """
    components = [c for c in (ontology.get("components") or []) if isinstance(c, str)]
    terms: List[str] = []

    for k in ("components", "interfaces", "keywords"):
        terms.extend([t for t in (ontology.get(k) or []) if isinstance(t, str)])

    terms = list(dict.fromkeys([t.strip() for t in terms if t.strip()]))
    return components, terms


def term_to_bucket_map() -> Dict[str, str]:
    """
    Maps matched ontology terms (lowercased) to your O-RAN ecosystem buckets.
    This prevents everything collapsing to 'RAN-General'.
    """
    return {
        # O-RAN interfaces / RIC
        "e2": "Near-RT RIC",
        "e2ap": "Near-RT RIC",
        "e2sm": "Near-RT RIC",
        "e2 interface": "Near-RT RIC",
        "a1": "Non-RT RIC",
        "a1 interface": "Non-RT RIC",
        "o1": "SMO",
        "o1 interface": "SMO",
        "open fronthaul": "O-RU",
        "fronthaul": "O-RU",
        "midhaul": "O-DU",
        "backhaul": "O-CU",
        "f1": "O-DU",
        "xn": "O-CU",
        "n2": "O-CU",
        "n3": "O-CU",
        "n6": "O-CU",

        # Protocols / management
        "netconf": "SMO",
        "yang": "SMO",
        "grpc": "Interfaces",
        "rest": "Interfaces",
        "http": "Interfaces",
        "http/2": "Interfaces",
        "sctp": "Interfaces",
        "ssh": "Interfaces",
        "tls": "Interfaces",
        "ipsec": "Interfaces",

        # O-Cloud / Kubernetes
        "o-cloud": "O-Cloud",
        "cloud": "O-Cloud",
        "private cloud": "O-Cloud",
        "public cloud": "O-Cloud",
        "hybrid cloud": "O-Cloud",
        "edge cloud": "O-Cloud",
        "kubernetes": "O-Cloud",
        "k8s": "O-Cloud",
        "container": "O-Cloud",
        "containers": "O-Cloud",
        "docker": "O-Cloud",
        "containerd": "O-Cloud",
        "cri": "O-Cloud",
        "pod": "O-Cloud",
        "namespace": "O-Cloud",
        "cluster": "O-Cloud",
        "deployment": "O-Cloud",
        "daemonset": "O-Cloud",
        "statefulset": "O-Cloud",
        "ingress": "O-Cloud",
        "load balancer": "O-Cloud",
        "cni": "O-Cloud",
        "multus": "O-Cloud",
        "sr-iov": "O-Cloud",
        "dpdk": "O-Cloud",
        "service mesh": "O-Cloud",
        "istio": "O-Cloud",
        "envoy": "O-Cloud",
        "sidecar": "O-Cloud",
        "mtls": "Interfaces",
        "etcd": "O-Cloud",
        "kube-apiserver": "O-Cloud",
        "kubelet": "O-Cloud",
        "kube-proxy": "O-Cloud",
        "admission controller": "O-Cloud",
        "network policy": "O-Cloud",
        "pod security": "O-Cloud",
        "configmap": "O-Cloud",

        # IAM / secrets
        "iam": "IAM",
        "identity": "IAM",
        "authentication": "IAM",
        "authorization": "IAM",
        "rbac": "IAM",
        "abac": "IAM",
        "sso": "IAM",
        "oauth": "IAM",
        "oidc": "IAM",
        "jwt": "IAM",
        "api key": "IAM",
        "token": "IAM",
        "session": "IAM",
        "certificate": "IAM",
        "pki": "IAM",
        "key management": "IAM",
        "kms": "IAM",
        "vault": "IAM",
        "hsm": "IAM",
        "mfa": "IAM",
        "least privilege": "IAM",
        "secret": "IAM",
        "secrets": "IAM",

        # CI/CD & supply chain
        "ci/cd": "CI/CD",
        "pipeline": "CI/CD",
        "gitlab": "CI/CD",
        "github actions": "CI/CD",
        "jenkins": "CI/CD",
        "runner": "CI/CD",
        "artifact": "CI/CD",
        "build": "CI/CD",
        "deploy": "CI/CD",
        "release": "CI/CD",
        "container image": "CI/CD",
        "registry": "CI/CD",
        "ecr": "CI/CD",
        "harbor": "CI/CD",
        "image signing": "CI/CD",
        "cosign": "CI/CD",
        "sbom": "CI/CD",
        "slsa": "CI/CD",
        "supply chain": "CI/CD",
        "dependency": "CI/CD",
        "package": "CI/CD",
        "typosquatting": "CI/CD",
        "backdoor update": "CI/CD",

        # SMO / management plane
        "smo": "SMO",
        "service management": "SMO",
        "orchestration": "SMO",
        "management plane": "SMO",
        "api": "SMO",
        "api gateway": "SMO",
        "openapi": "SMO",
        "swagger": "SMO",
        "telemetry": "SMO",
        "observability": "SMO",
        "monitoring": "SMO",
        "logging": "SMO",

        # Telecom / RAN general
        "o-ran": "RAN-General",
        "open ran": "RAN-General",
        "ran": "RAN-General",
        "gnb": "RAN-General",
        "du": "O-DU",
        "ru": "O-RU",
        "cu": "O-CU",
        "cu-cp": "O-CU",
        "cu-up": "O-CU",
        "radio access": "RAN-General",
        "telecom": "RAN-General",
        "5g": "RAN-General",
        "4g": "RAN-General",
        "lte": "RAN-General",
        "nr": "RAN-General",
        "edge": "RAN-General",
        "mec": "RAN-General",
        "control plane": "RAN-General",
        "user plane": "RAN-General",
        "signaling": "RAN-General",

        # Apps
        "xapp": "Near-RT RIC",
        "rapp": "Non-RT RIC",
        "xApp": "Near-RT RIC",
        "rApp": "Non-RT RIC",
    }


def map_to_oran_buckets(
    text: str,
    model: SentenceTransformer,
    term_emb: np.ndarray,
    terms: List[str],
    components: List[str],
) -> List[Tuple[str, float, str]]:
    """
    Returns list of (bucket, similarity, matched_term) for top-K matched ontology terms.
    """
    q = model.encode([text], normalize_embeddings=True)[0]
    top = cosine_topk(q, term_emb, TOP_K_COMPONENTS)

    t2b = term_to_bucket_map()
    results: List[Tuple[str, float, str]] = []

    for idx, sim in top:
        term = terms[idx]
        t = term.lower()

        # direct match for ontology component labels
        comp_exact = next((c for c in components if c.lower() == t), None)
        if comp_exact:
            # Map components to buckets: if it’s not in BUCKETS, treat as Interfaces/RAN-General
            if comp_exact in BUCKETS:
                bucket = comp_exact
            else:
                # interface-like or unknown ontology component label
                bucket = t2b.get(t, "RAN-General")
            results.append((bucket, sim, term))
            continue

        bucket = t2b.get(t, "RAN-General")
        # Guard: only allow known buckets
        if bucket not in BUCKETS:
            bucket = "RAN-General"
        results.append((bucket, sim, term))

    return results


# ------------------------
# Main pipeline
# ------------------------

def main():
    ontology = load_json(ORAN_ONTOLOGY_PATH)
    components, terms = build_oran_terms(ontology)

    # Build model + ontology embeddings
    model = SentenceTransformer(MODEL_NAME)
    term_emb = model.encode(terms, normalize_embeddings=True)

    # Fetch STIX objects
    objects = fetch_attack_objects()

    # Mitigation links
    mitigation_map = build_mitigation_map(objects)

    # Techniques (attack-pattern)
    techniques = [o for o in objects if isinstance(o, dict) and o.get("type") == "attack-pattern"]

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    kept_technique_ids: Set[str] = set()
    kept_mitigation_ids: Set[str] = set()

    # Add bucket nodes
    for b in BUCKETS:
        nodes.append({"id": f"oran:{b}", "type": "oran-bucket", "name": b})

    # Score + keep techniques
    for ap in techniques:
        ap_id = ap.get("id")
        if not ap_id:
            continue

        if is_deprecated(ap):
            continue

        text = stix_text(ap)
        if not text:
            continue

        mapped = map_to_oran_buckets(text, model, term_emb, terms, components)
        if not mapped:
            continue

        best_bucket, best_sim, best_term = max(mapped, key=lambda x: x[1])

        if best_sim < RELEVANCE_THRESHOLD:
            continue

        kept_technique_ids.add(ap_id)

        nodes.append({
            "id": f"tech:{ap_id}",
            "type": "attack-pattern",
            "stix_id": ap_id,
            "external_id": get_external_id(ap),
            "name": ap.get("name"),
            "relevance": best_sim,
            "best_term": best_term,
            "bucket": best_bucket,
            "description": (ap.get("description") or "")[:MAX_DESC_CHARS],
        })

        # edges: technique -> bucket (top-K)
        for bucket, sim, term in mapped:
            edges.append({
                "source": f"tech:{ap_id}",
                "target": f"oran:{bucket}",
                "type": "targets_bucket",
                "weight": sim,
                "evidence_term": term,
            })

    # Add mitigations connected to kept techniques
    for ap_id in list(kept_technique_ids):
        for coa in mitigation_map.get(ap_id, []):
            mid = coa.get("id")
            if not mid:
                continue

            if mid not in kept_mitigation_ids:
                kept_mitigation_ids.add(mid)
                nodes.append({
                    "id": f"mit:{mid}",
                    "type": "course-of-action",
                    "stix_id": mid,
                    "external_id": get_external_id(coa),
                    "name": coa.get("name"),
                    "description": (coa.get("description") or "")[:MAX_DESC_CHARS],
                })

            edges.append({
                "source": f"tech:{ap_id}",
                "target": f"mit:{mid}",
                "type": "mitigated_by",
            })

    # Export
    (OUT_DIR / "oran_pruned_nodes.json").write_text(json.dumps(nodes, indent=2), encoding="utf-8")
    (OUT_DIR / "oran_pruned_edges.json").write_text(json.dumps(edges, indent=2), encoding="utf-8")

    print(f"\nSaved nodes: {OUT_DIR / 'oran_pruned_nodes.json'} ({len(nodes)})")
    print(f"Saved edges: {OUT_DIR / 'oran_pruned_edges.json'} ({len(edges)})")
    print(f"Kept techniques: {len(kept_technique_ids)}")
    print(f"Kept mitigations: {len(kept_mitigation_ids)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)