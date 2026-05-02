'''
 - Evaluate how relevant each STIX object is to Open RAN and discards the irrelevant ones.
 - Uses semantic similarity (sentence transformers) to compare object descriptions against ORAN ontology keywords.
-  Implements a "Max-Sim" strategy: if an object matches ANY keyword well, it is retained, even if it doesn't match others.
-  This allows us to keep niche but relevant objects (e.g., a Linux kernel exploit that is highly relevant to O-DU but not to "Radio").
-  Also includes optional summarization for mid-tier relevance objects to reduce noise while retaining key info.
-  Custom tagging for O-DU related objects based on keyword presence.
-  Saves the pruned bundle in a compressed format for efficient storage and faster loading in later stages.
'''


# Logic is based on the graph nature of STIX bundles.
# Nodes(SDO) + Edges(SRO) + Attributes = Knowledge Graph
# We want to keep nodes that are relevant to ORAN, even if they are not directly connected to other nodes. Hence the Max-Sim strategy.

from stix2 import parse, Bundle
from sentence_transformers import SentenceTransformer, util
import json
import gzip
import os


def prune_stix_bundle(bundle_path="raw_data/attck_bundle.json", 
                      output_dir="processed_data",
                      ontology_path="oran_ontology.json",
                      min_threshold=25):
    """
    Prune STIX bundle using semantic similarity with ORAN ontology
    
    Args:
        bundle_path: Path to input STIX bundle JSON
        output_dir: Directory for output pruned bundle
        ontology_path: Path to ORAN ontology JSON
        min_threshold: Minimum relevance threshold (0-100)
    
    Returns:
        Pruned bundle object
    """
    
    # Setup
    print("Loading sentence transformer model...")
    model = SentenceTransformer('all-MiniLM-L6-v2')

    # Load Ontology and FLATTEN it into a list of keywords
    print(f"Loading ontology from {ontology_path}...")
    with open(ontology_path, "r") as f:
        ontology = json.load(f)
    
    # We want a list of individual terms, not one giant string
    ontology_keywords = ontology["components"] + ontology["interfaces"] + ontology["keywords"]
    print(f"  Loaded {len(ontology_keywords)} ontology keywords for Max-Sim comparison.")

    # Pre-encode ontology keywords (efficiency boost)
    print("Pre-encoding ontology keywords...")
    ontology_embeddings = model.encode(ontology_keywords)

    # Load Raw Data
    print(f"Loading STIX bundle from {bundle_path}...")
    with open(bundle_path, "r") as f:
        raw_bundle = json.load(f)
    
    print(f"  Loaded {len(raw_bundle)} raw objects")

    lite_objects = []
    pruned_count = 0

    print(f"Starting pruning process with Max-Sim Strategy (threshold: {min_threshold}%)...")

    for idx, obj in enumerate(raw_bundle):
        # Skip non-data objects
        if obj.get('type') == 'bundle': 
            continue

        # Prepare text
        text = f"{obj.get('name', '')} {obj.get('description', '')}"
        
        # --- NEW SCORING LOGIC ---
        embedding_text = model.encode(text)
        
        # Calculate cosine similarity against ALL keywords at once
        # This returns a list of scores, one for each keyword
        cos_scores = util.cos_sim(embedding_text, ontology_embeddings)[0]
        
        # Take the MAXIMUM score (Best Match)
        # e.g., if it matches "Linux" very well (80%) but "Radio" poorly (5%), 
        # the score is 80, not the average (42.5).
        best_score = cos_scores.max().item() * 100
        
        # -------------------------

        # logging (optional, reduced noise)
        if best_score > 25:
            print(f"  ✓ Keep: {obj.get('name', 'Unknown')[:40]:40} | Score: {best_score:6.2f}%")

        # Thresholds (Adjusted for Max-Sim)
        if best_score < min_threshold: 
            pruned_count += 1
            continue
            
        # Summarization for mid-tier relevance
        if best_score < 50:
            desc = obj.get("description", "")
            obj["description"] = desc[:200] + "..." if len(desc) > 200 else desc

        # Custom Tagging (Case insensitive)
        if "o-du" in text.lower():
            obj["x_oran_component"] = "O-DU"
            
        # Re-parse to STIX object
        try:
            parsed_obj = parse(obj, allow_custom=True)
            lite_objects.append(parsed_obj)
        except Exception as e:
            print(f"  ⚠ Skipping invalid STIX object: {e}")

    # Save
    lite_bundle = Bundle(objects=lite_objects, allow_custom=True)
    os.makedirs(output_dir, exist_ok=True)
    serialized = lite_bundle.serialize(pretty=True)

    output_file = os.path.join(output_dir, "lite_bundle.json.gz")
    with gzip.open(output_file, "wt") as f:
        f.write(serialized)

    print(f"\n✓ Pruning Summary:")
    print(f"  Original Objects: {len(raw_bundle)}")
    print(f"  Pruned Objects: {pruned_count}")
    print(f"  Retained Objects: {len(lite_objects)}")
    print(f"  Retention Rate: {len(lite_objects)/len(raw_bundle)*100:.1f}%")
    print(f"✓ Pruned bundle saved to: {output_file}")
    
    return lite_bundle


if __name__ == "__main__":
    prune_stix_bundle()