"""
Data Transformer: Convert O-RAN STIX graph data into consolidated threat knowledge base format

This module transforms the pruned nodes and edges from STIX knowledge graph into
a unified threat document format suitable for RAG indexing.

Input: oran_pruned_nodes.json, oran_pruned_edges.json
Output: threat_knowledge_base.json (consolidated threat records)
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class ThreatRecord:
    """Unified threat record combining attack technique, related buckets, and mitigations"""
    threat_id: str  # Unique ID from ATT&CK (e.g., T1497)
    threat_name: str  # Technique name
    threat_description: str  # Full description
    threat_type: str  # "attack-pattern", "technique", etc.
    mitre_id: Optional[str] = None  # MITRE ATT&CK ID
    
    # O-RAN specific
    affected_components: List[str] = None  # List of O-RAN components
    oran_buckets: List[str] = None  # O-Cloud, SMO, Near-RT RIC, etc.
    evidence_terms: List[str] = None  # Matched ontology terms
    
    # Mitigation
    mitigations: List[Dict[str, str]] = None  # [{mitigation_id, mitigation_name, description}, ...]
    mitigation_techniques: List[str] = None  # Related mitigation techniques
    
    # Index
    keywords: List[str] = None  # Searchable keywords
    severity: str = "medium"  # low, medium, high, critical
    
    # Metadata
    created_date: str = None
    last_updated: str = None
    source: str = "MITRE-ATT&CK"  # Source of knowledge
    custom: bool = False  # Whether this is a custom/uploaded record
    
    def __post_init__(self):
        if self.affected_components is None:
            self.affected_components = []
        if self.oran_buckets is None:
            self.oran_buckets = []
        if self.evidence_terms is None:
            self.evidence_terms = []
        if self.mitigations is None:
            self.mitigations = []
        if self.mitigation_techniques is None:
            self.mitigation_techniques = []
        if self.keywords is None:
            self.keywords = []
        if self.created_date is None:
            self.created_date = datetime.now().isoformat()
        if self.last_updated is None:
            self.last_updated = datetime.now().isoformat()


class DataTransformer:
    """Transform STIX graph data into threat knowledge base"""
    
    def __init__(self, nodes_path: Path, edges_path: Path):
        """
        Args:
            nodes_path: Path to oran_pruned_nodes.json
            edges_path: Path to oran_pruned_edges.json
        """
        self.nodes_path = nodes_path
        self.edges_path = edges_path
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.threat_records: List[ThreatRecord] = []
        
    def load_data(self):
        """Load nodes and edges from JSON files"""
        print("Loading STIX graph data...")
        
        with open(self.nodes_path, 'r', encoding='utf-8') as f:
            self.nodes = json.load(f)
        
        with open(self.edges_path, 'r', encoding='utf-8') as f:
            self.edges = json.load(f)
        
        print(f"  Loaded {len(self.nodes)} nodes and {len(self.edges)} edges")
    
    def extract_mitre_id(self, node_id: str, name: str) -> Optional[str]:
        """Extract MITRE ATT&CK ID from node name (e.g., 'T1497.001')"""
        if isinstance(name, str):
            # Try to find pattern like T1497 or T1497.001
            import re
            match = re.search(r'T\d{4}(?:\.\d{3})?', name)
            if match:
                return match.group(0)
        return None
    
    def get_edges_for_technique(self, technique_id: str) -> Dict[str, List]:
        """Get all edges connected to a technique"""
        related_edges = {
            "component_related": [],
            "mitigations": [],
            "other": []
        }
        
        for edge in self.edges:
            source = edge.get("source", "")
            target = edge.get("target", "")
            rel_type = edge.get("type", edge.get("relationship", "related-to"))
            evidence = edge.get("evidence_term", "")
            
            # Find edges where this technique is the source and target is a bucket
            if source == technique_id and "oran:" in target:
                # Extract bucket name (e.g., "oran:RAN-General" -> "RAN-General")
                bucket_name = target.replace("oran:", "").strip()
                related_edges["component_related"].append({
                    "component": bucket_name,
                    "evidence_term": evidence
                })
            
            # Find edges where this technique is the source and target is a mitigation
            if source == technique_id and "mit:" in target:
                related_edges["mitigations"].append({
                    "mitigation_id": target.replace("mit:", ""),
                    "evidence_term": evidence
                })
            
            # Other relationships
            if (source == technique_id or target == technique_id) and \
               not ("oran:" in target or "mit:" in target or "oran:" in source or "mit:" in source):
                related_edges["other"].append({
                    "source": source,
                    "target": target,
                    "type": rel_type
                })
        
        return related_edges
    
    def find_mitigation_details(self, mitigation_id: str) -> Optional[Dict[str, str]]:
        """Find mitigation node details"""
        # Ensure mit: prefix is included
        full_mitigation_id = f"mit:{mitigation_id}" if not mitigation_id.startswith("mit:") else mitigation_id
        
        for node in self.nodes:
            if node.get("id") == full_mitigation_id:
                return {
                    "mitigation_id": mitigation_id,
                    "mitigation_name": node.get("name", "Unknown"),
                    "description": node.get("description", "")[:500] or "No description"
                }
        return None
    
    def transform(self) -> List[ThreatRecord]:
        """Transform STIX graph data into threat records"""
        print("\nTransforming STIX graph data...")
        
        mitigation_cache = {}
        
        # First pass: create all threat records
        all_threats = {}
        
        # Process each technique node
        for node in self.nodes:
            node_type = node.get("type", "")
            
            # Skip bucket nodes (we only want techniques and mitigations)
            if node_type == "oran-bucket":
                continue
            
            # Only process attack techniques (can be "technique" or "attack-pattern")
            if node_type not in ["technique", "attack-pattern"]:
                continue
            
            node_id = node.get("id", "")
            if not node_id.startswith("tech:"):
                continue
            
            node_id = node_id.replace("tech:", "")
            name = node.get("name", "Unknown")
            description = node.get("description", "No description")
            bucket = node.get("bucket", "Unknown")
            
            # Extract MITRE ID
            mitre_id = self.extract_mitre_id(node_id, name)
            
            # Get all related edges
            edges_info = self.get_edges_for_technique(f"tech:{node_id}")
            
            # Extract components and buckets
            affected_components = []
            oran_buckets = []
            evidence_terms = []
            
            for comp_edge in edges_info["component_related"]:
                comp_name = comp_edge["component"]
                affected_components.append(comp_name)
                oran_buckets.append(comp_name)
                if comp_edge["evidence_term"]:
                    evidence_terms.append(comp_edge["evidence_term"])
            
            # Remove duplicates
            oran_buckets = list(set(oran_buckets))
            evidence_terms = list(set(evidence_terms))
            
            # Extract mitigations
            mitigations = []
            for mit_edge in edges_info["mitigations"]:
                mit_id = mit_edge["mitigation_id"]
                
                # Use cache to avoid repeated lookups
                if mit_id not in mitigation_cache:
                    mitigation_cache[mit_id] = self.find_mitigation_details(mit_id)
                
                if mitigation_cache[mit_id]:
                    mitigations.append(mitigation_cache[mit_id])
            
            # Generate keywords for search
            keywords = [name, *[b for b in oran_buckets], *evidence_terms]
            if mitre_id:
                keywords.append(mitre_id)
            keywords = list(set(keywords))
            
            # Determine severity (can be enhanced with logic)
            severity = "high" if len(mitigations) > 0 else "medium"
            
            # Create threat record
            threat_record = ThreatRecord(
                threat_id=node_id,
                threat_name=name,
                threat_description=description,
                threat_type="attack-pattern",
                mitre_id=mitre_id,
                affected_components=affected_components,
                oran_buckets=oran_buckets,
                evidence_terms=evidence_terms,
                mitigations=mitigations,
                mitigation_techniques=[],  # Will be populated in second pass
                keywords=keywords,
                severity=severity,
                source="MITRE-ATT&CK"
            )
            
            # Store with technique ID as key for second pass
            all_threats[f"tech:{node_id}"] = {
                "record": threat_record,
                "mitigations": [m.get("mitigation_id") for m in mitigations]
            }
        
        # Second pass: populate mitigation_techniques by finding techniques with shared mitigations
        print("  Populating mitigation techniques (cross-referencing)...")
        for tech_id, threat_data in all_threats.items():
            threat_record = threat_data["record"]
            threat_mitigations = set(threat_data["mitigations"])
            
            if threat_mitigations:
                # Find all other techniques that share at least one mitigation
                related_techniques = []
                
                for other_tech_id, other_threat_data in all_threats.items():
                    if other_tech_id == tech_id:
                        continue  # Skip self
                    
                    other_mitigations = set(other_threat_data["mitigations"])
                    
                    # If they share a mitigation, they're strategically related
                    if threat_mitigations & other_mitigations:
                        other_record = other_threat_data["record"]
                        related_techniques.append({
                            "technique_id": other_record.threat_id,
                            "technique_name": other_record.threat_name,
                            "mitre_id": other_record.mitre_id,
                            "relationship": "shares_mitigation"
                        })
                
                threat_record.mitigation_techniques = related_techniques
            
            self.threat_records.append(threat_record)
        
        print(f"  Created {len(self.threat_records)} threat records")
        print(f"  Found {sum(1 for t in self.threat_records if t.mitigation_techniques)} threats with related techniques")
        return self.threat_records
    
    def save_threat_kb(self, output_path: Path):
        """Save threat knowledge base to JSON"""
        print(f"\nSaving threat knowledge base to {output_path}...")
        
        kb_data = {
            "metadata": {
                "total_threats": len(self.threat_records),
                "created_date": datetime.now().isoformat(),
                "source": "MITRE-ATT&CK + O-RAN Ontology"
            },
            "threats": [asdict(record) for record in self.threat_records]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(kb_data, f, indent=2, ensure_ascii=False)
        
        print(f"  Saved {len(self.threat_records)} threats to knowledge base")


def main():
    """Main transformation pipeline"""
    
    # Paths - handle both running from root and from rag directory
    # When run from rag directory (setup.bat), use ../pipeline/...
    # When run from root, use pipeline/...
    nodes_candidates = [
        Path("../pipeline/oran_outputs/oran_pruned_nodes.json"),  # From rag/
        Path("pipeline/oran_outputs/oran_pruned_nodes.json"),      # From root
    ]
    edges_candidates = [
        Path("../pipeline/oran_outputs/oran_pruned_edges.json"),   # From rag/
        Path("pipeline/oran_outputs/oran_pruned_edges.json"),      # From root
    ]
    output_path = Path("data/threat_knowledge_base.json")
    
    # Find the correct paths
    nodes_path = None
    edges_path = None
    for candidate in nodes_candidates:
        if candidate.exists():
            nodes_path = candidate
            break
    for candidate in edges_candidates:
        if candidate.exists():
            edges_path = candidate
            break
    
    # Validate paths
    if nodes_path is None:
        raise FileNotFoundError(f"Nodes file not found. Tried: {nodes_candidates}")
    if edges_path is None:
        raise FileNotFoundError(f"Edges file not found. Tried: {edges_candidates}")
    
    # Transform
    transformer = DataTransformer(nodes_path, edges_path)
    transformer.load_data()
    transformer.transform()
    
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    transformer.save_threat_kb(output_path)
    
    print("\n✓ Data transformation complete!")
    print(f"  Knowledge base saved to: {output_path.resolve()}")


if __name__ == "__main__":
    main()
