import json
from pathlib import Path
from collections import defaultdict
from pyvis.network import Network

NODES_PATH = Path("oran_outputs/oran_pruned_nodes.json")
EDGES_PATH = Path("oran_outputs/oran_pruned_edges.json")
OUT_HTML = Path("oran_outputs/oran_network_clean.html")

# --- TUNING ---
SHOW_BUCKETS = {"O-Cloud", "SMO", "Near-RT RIC", "Non-RT RIC", "IAM", "CI/CD", "Interfaces"}
MAX_TECHNIQUES_PER_BUCKET = 40     # reduce clutter
MAX_MITIGATIONS_PER_TECHNIQUE = 8  # reduce clutter

def main():
    nodes = json.loads(NODES_PATH.read_text(encoding="utf-8"))
    edges = json.loads(EDGES_PATH.read_text(encoding="utf-8"))

    # Index nodes
    node_by_id = {n["id"]: n for n in nodes}

    # Split nodes by type
    bucket_nodes = {nid for nid, n in node_by_id.items() if n.get("type") == "oran-bucket"}
    tech_nodes = {nid for nid, n in node_by_id.items() if n.get("type") == "attack-pattern"}
    mit_nodes = {nid for nid, n in node_by_id.items() if n.get("type") == "course-of-action"}

    # Build adjacency
    bucket_to_tech = defaultdict(list)
    tech_to_mit = defaultdict(list)

    for e in edges:
        src, tgt, etype = e["source"], e["target"], e.get("type")

        if etype == "targets_bucket" and src in tech_nodes and tgt in bucket_nodes:
            bucket_to_tech[tgt].append(src)

        if etype == "mitigated_by" and src in tech_nodes and tgt in mit_nodes:
            tech_to_mit[src].append(tgt)

    # Filter buckets
    selected_bucket_ids = {f"oran:{b}" for b in SHOW_BUCKETS if f"oran:{b}" in bucket_nodes}

    # Pick top techniques per bucket by relevance
    selected_tech_ids = set()
    for b in selected_bucket_ids:
        techs = bucket_to_tech.get(b, [])
        techs_sorted = sorted(
            techs,
            key=lambda tid: float(node_by_id.get(tid, {}).get("relevance", 0.0)),
            reverse=True
        )
        selected_tech_ids.update(techs_sorted[:MAX_TECHNIQUES_PER_BUCKET])

    # Pick mitigations for selected techniques
    selected_mit_ids = set()
    for t in selected_tech_ids:
        mits = tech_to_mit.get(t, [])
        selected_mit_ids.update(mits[:MAX_MITIGATIONS_PER_TECHNIQUE])

    # Build the network (static hierarchical)
    net = Network(height="900px", width="100%", directed=True, bgcolor="#ffffff", font_color="#111111")
    net.set_options("""
    var options = {
    "physics": {
        "enabled": false
    },
    "layout": {
        "hierarchical": {
        "enabled": true,
        "direction": "LR",
        "sortMethod": "directed",
        "levelSeparation": 220,
        "nodeSpacing": 180,
        "treeSpacing": 240
        }
    },
    "interaction": {
        "hover": true,
        "selectConnectedEdges": true,
        "multiselect": false
    },
    "edges": {
        "arrows": {
        "to": { "enabled": true }
        },
        "smooth": {
        "type": "cubicBezier"
        },
        "color": {
        "color": "#888888",
        "highlight": "#ff0000",
        "hover": "#ff0000"
        },
        "width": 1,
        "selectionWidth": 4
    },
    "nodes": {
        "borderWidth": 1,
        "borderWidthSelected": 4,
        "color": {
        "border": "#2B7CE9",
        "background": "#97C2FC",
        "highlight": {
            "border": "#ff0000",
            "background": "#FFD1D1"
        }
        }
    }
    }
    """)

    # Add bucket nodes at level 0
    for bid in sorted(selected_bucket_ids):
        b = node_by_id[bid]
        net.add_node(
            bid,
            label=b.get("name", bid),
            title=f"<b>{b.get('name', bid)}</b><br>type: bucket",
            level=0,
            shape="box",
            size=25
        )

    # Add technique nodes at level 1
    for tid in selected_tech_ids:
        t = node_by_id.get(tid, {})
        label = t.get("external_id") or (t.get("name") or "tech")
        title = f"<b>{t.get('name','')}</b><br>ATT&CK: {t.get('external_id','')}<br>relevance: {t.get('relevance',0):.3f}<br>bucket: {t.get('bucket','')}"
        net.add_node(tid, label=label, title=title, level=1, shape="ellipse", size=15)

    # Add mitigation nodes at level 2
    for mid in selected_mit_ids:
        m = node_by_id.get(mid, {})
        label = m.get("external_id") or (m.get("name") or "mit")
        title = f"<b>{m.get('name','')}</b><br>MITIGATION: {m.get('external_id','')}"
        net.add_node(mid, label=label, title=title, level=2, shape="box", size=12)

    # Add edges: bucket -> technique
    for e in edges:
        if e.get("type") != "targets_bucket":
            continue
        src, tgt = e["source"], e["target"]
        if src in selected_tech_ids and tgt in selected_bucket_ids:
            w = e.get("weight", None)
            title = f"targets_bucket"
            if w is not None:
                title += f" | score={float(w):.3f}"
            net.add_edge(tgt, src, title=title)

    # Add edges: technique -> mitigation
    for e in edges:
        if e.get("type") != "mitigated_by":
            continue
        src, tgt = e["source"], e["target"]
        if src in selected_tech_ids and tgt in selected_mit_ids:
            net.add_edge(src, tgt, title="mitigated_by")

    net.write_html(str(OUT_HTML), open_browser=False, notebook=False)
    print(f"Saved: {OUT_HTML.resolve()}")

if __name__ == "__main__":
    main()