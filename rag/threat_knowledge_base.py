"""
Threat Knowledge Base Manager

Uses ChromaDB (free, open-source vector database) to store and retrieve
threat information with semantic search capabilities.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
import chromadb
from sentence_transformers import SentenceTransformer
from datetime import datetime
import hashlib


class ThreatKnowledgeBase:
    """Manage threat knowledge base with vector search using ChromaDB"""
    
    def __init__(self, kb_dir: Path = None, embedding_model: str = "all-MiniLM-L6-v2"):
        """
        Initialize knowledge base manager
        
        Args:
            kb_dir: Directory to store ChromaDB data. If None, uses ./data (current dir)
            embedding_model: HuggingFace model for embeddings (free, no API key needed)
        """
        # Smart path detection
        if kb_dir is None:
            # Use current directory's data/ folder
            self.kb_dir = Path("data")
        else:
            self.kb_dir = Path(kb_dir)
        
        self.kb_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize ChromaDB with new client API
        try:
            # Try new API first (ChromaDB >= 0.4.0)
            self.chroma_client = chromadb.PersistentClient(
                path=str(self.kb_dir / "chromadb")
            )
        except TypeError:
            # Fallback to older API if new one not available
            try:
                self.chroma_client = chromadb.Client()
            except:
                # Last resort: create ephemeral client
                self.chroma_client = chromadb.EphemeralClient()
        
        # Initialize embedding model (downloaded once, cached locally)
        print(f"Loading embedding model: {embedding_model}")
        self.embedding_model = SentenceTransformer(embedding_model)
        
        # Get or create collection
        self.collection = self.chroma_client.get_or_create_collection(
            name="threat_knowledge_base",
            metadata={"hnsw:space": "cosine"}
        )
        
        self.kb_json_path = self.kb_dir / "threat_knowledge_base.json"
        self.threats_by_id = {}
        self._load_kb_from_json()
    
    def _load_kb_from_json(self):
        """Load threat knowledge base from JSON file"""
        if self.kb_json_path.exists():
            print(f"Loading knowledge base from {self.kb_json_path}")
            with open(self.kb_json_path, 'r', encoding='utf-8') as f:
                kb_data = json.load(f)
                self.threats_by_id = {threat["threat_id"]: threat for threat in kb_data.get("threats", [])}
            print(f"  Loaded {len(self.threats_by_id)} threats")
    
    def _save_kb_to_json(self):
        """Save current knowledge base to JSON"""
        kb_data = {
            "metadata": {
                "total_threats": len(self.threats_by_id),
                "last_updated": datetime.now().isoformat(),
            },
            "threats": list(self.threats_by_id.values())
        }
        with open(self.kb_json_path, 'w', encoding='utf-8') as f:
            json.dump(kb_data, f, indent=2, ensure_ascii=False)
    
    def _generate_doc_id(self, threat_id: str) -> str:
        """Generate unique document ID"""
        return hashlib.md5(f"threat_{threat_id}".encode()).hexdigest()
    
    def index_threats(self, force_reindex: bool = False):
        """Index all threats in ChromaDB for semantic search"""
        if len(self.collection.get()["ids"]) > 0 and not force_reindex:
            print(f"Knowledge base already indexed with {len(self.collection.get()['ids'])} documents")
            return
        
        print("Indexing threats in ChromaDB...")
        
        # Clear existing
        if force_reindex:
            self.collection.delete(where={})
        
        documents = []
        ids = []
        metadatas = []
        embeddings_list = []
        
        for threat_id, threat in self.threats_by_id.items():
            # Create comprehensive document text for embedding
            doc_text = f"""
            Threat: {threat.get('threat_name', '')}
            ID: {threat_id}
            MITRE ID: {threat.get('mitre_id', 'N/A')}
            
            Description: {threat.get('threat_description', '')}
            
            Affected O-RAN Components: {', '.join(threat.get('oran_buckets', []))}
            Evidence Terms: {', '.join(threat.get('evidence_terms', []))}
            
            Mitigations:
            """
            
            for mit in threat.get('mitigations', []):
                doc_text += f"\n  - {mit.get('mitigation_name', '')}: {mit.get('description', '')}"
            
            # Generate embedding
            embedding = self.embedding_model.encode(doc_text)
            
            doc_id = self._generate_doc_id(threat_id)
            documents.append(doc_text)
            ids.append(doc_id)
            embeddings_list.append(embedding.tolist())
            
            # Metadata must be strings for ChromaDB compatibility
            metadatas.append({
                "threat_id": str(threat_id),
                "threat_name": str(threat.get("threat_name", "")),
                "mitre_id": str(threat.get("mitre_id", "")),
                "severity": str(threat.get("severity", "medium")),
                "custom": str(threat.get("custom", False))
            })
        
        # Add to ChromaDB in batches to avoid memory issues
        batch_size = 50
        for i in range(0, len(documents), batch_size):
            batch_end = min(i + batch_size, len(documents))
            try:
                self.collection.add(
                    documents=documents[i:batch_end],
                    ids=ids[i:batch_end],
                    embeddings=embeddings_list[i:batch_end],
                    metadatas=metadatas[i:batch_end]
                )
                print(f"  Indexed batch {batch_end}/{len(documents)} threats...")
            except Exception as e:
                print(f"  Warning: Error indexing batch {i}-{batch_end}: {e}")
        
        print(f"  ✓ Indexed {len(documents)} threats in ChromaDB")
    
    def search_threats(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Semantic search for relevant threats
        
        Args:
            query: Natural language search query
            top_k: Number of results to return
        
        Returns:
            List of threat records with relevance scores
        """
        # Generate query embedding
        query_embedding = self.embedding_model.encode(query)
        
        # Search in ChromaDB
        results = self.collection.query(
            query_embeddings=[query_embedding.tolist()],
            n_results=top_k
        )
        
        # Format results
        formatted_results = []
        for i, threat_id in enumerate(results.get("metadatas", [[]])[0]):
            threat_record = self.threats_by_id.get(threat_id.get("threat_id"))
            if threat_record:
                formatted_results.append({
                    "threat": threat_record,
                    "relevance_score": 1 - (results.get("distances", [[]])[0][i] / 2)  # Convert distance to similarity
                })
        
        return formatted_results
    
    def add_threat(self, threat_data: Dict[str, Any]) -> bool:
        """
        Add or update a threat record
        
        Args:
            threat_data: Threat record dictionary
        
        Returns:
            True if successful
        """
        threat_id = threat_data.get("threat_id")
        if not threat_id:
            print("Error: threat_id is required")
            return False
        
        # Update timestamp
        threat_data["last_updated"] = datetime.now().isoformat()
        if "created_date" not in threat_data:
            threat_data["created_date"] = datetime.now().isoformat()
        threat_data["custom"] = True
        
        # Add to memory
        self.threats_by_id[threat_id] = threat_data
        
        # Save to JSON
        self._save_kb_to_json()
        
        # Re-index this threat
        doc_text = f"""
        Threat: {threat_data.get('threat_name', '')}
        ID: {threat_id}
        Description: {threat_data.get('threat_description', '')}
        Affected Components: {', '.join(threat_data.get('oran_buckets', []))}
        """
        
        query_embedding = self.embedding_model.encode(doc_text)
        doc_id = self._generate_doc_id(threat_id)
        
        # Upsert in ChromaDB
        self.collection.upsert(
            documents=[doc_text],
            ids=[doc_id],
            embeddings=[query_embedding.tolist()],
            metadatas=[{
                "threat_id": threat_id,
                "threat_name": threat_data.get("threat_name", ""),
                "severity": threat_data.get("severity", "medium"),
                "custom": "True"
            }]
        )
        
        print(f"✓ Threat '{threat_id}' added/updated")
        return True
    
    def get_threat(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific threat by ID"""
        return self.threats_by_id.get(threat_id)
    
    def delete_threat(self, threat_id: str) -> bool:
        """Delete a threat record"""
        if threat_id in self.threats_by_id:
            del self.threats_by_id[threat_id]
            self._save_kb_to_json()
            
            # Remove from ChromaDB
            doc_id = self._generate_doc_id(threat_id)
            self.collection.delete(ids=[doc_id])
            
            print(f"✓ Threat '{threat_id}' deleted")
            return True
        return False
    
    def list_threats(self, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """List all threats with pagination"""
        threat_list = list(self.threats_by_id.values())
        total = len(threat_list)
        
        paginated = threat_list[offset:offset + limit]
        
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "threats": paginated
        }
    
    def get_kb_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics"""
        total_threats = len(self.threats_by_id)
        
        components = set()
        mitigations = set()
        severities = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for threat in self.threats_by_id.values():
            components.update(threat.get("oran_buckets", []))
            severities[threat.get("severity", "medium")] += 1
            mitigations.update(
                [m.get("mitigation_id") for m in threat.get("mitigations", [])]
            )
        
        return {
            "total_threats": total_threats,
            "total_components": len(components),
            "total_mitigations": len(mitigations),
            "severity_distribution": severities,
            "components": list(components),
            "indexed_documents": len(self.collection.get()["ids"])
        }


def main():
    """Initialize and test knowledge base"""
    
    kb = ThreatKnowledgeBase()
    kb.index_threats()
    
    # Print stats
    stats = kb.get_kb_stats()
    print("\n📊 Knowledge Base Statistics:")
    print(f"  Total Threats: {stats['total_threats']}")
    print(f"  Affected Components: {stats['total_components']}")
    print(f"  Mitigations: {stats['total_mitigations']}")
    print(f"  Severity Distribution: {stats['severity_distribution']}")
    
    # Test search
    print("\n🔍 Testing semantic search...")
    results = kb.search_threats("detecting virtualization sandbox evasion", top_k=3)
    for i, result in enumerate(results, 1):
        print(f"  {i}. {result['threat']['threat_name']} (Score: {result['relevance_score']:.2f})")


if __name__ == "__main__":
    main()
