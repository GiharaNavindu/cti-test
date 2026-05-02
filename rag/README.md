# O-RAN Threat RAG System

A comprehensive **Retrieval-Augmented Generation (RAG)** system for O-RAN cybersecurity threat intelligence. This system combines semantic search with Google Gemini AI to analyze threats, provide mitigation strategies, and maintain an evolving knowledge base.

## Features

- **🎯 Semantic Threat Search**: Find relevant threats using natural language queries
- **🤖 AI-Powered Analysis**: Generate comprehensive threat analysis and recommendations using Gemini
- **📚 Intelligent Knowledge Base**: ChromaDB-backed vector database with 10,000+ MITRE ATT&CK threats
- **🔧 Knowledge Base Management**: Add, edit, delete, and manage threat records
- **🌐 Web Interface**: Beautiful, responsive UI for managing threats and analyzing attacks
- **📊 Real-time Statistics**: Dashboard with threat distribution and component analysis
- **🔗 Internet Search**: Automatic internet search for novel/unknown threats
- **💾 Import/Export**: Backup and restore knowledge base in JSON format
- **🚀 REST API**: Comprehensive API for programmatic access

## Technology Stack

### Free & Open-Source Technologies

- **Vector Database**: ChromaDB (free, local, no cloud dependency)
- **Embeddings**: Sentence-Transformers (all-MiniLM-L6-v2) - free, no API key needed
- **LLM**: Google Gemini API (free tier with limits)
- **Web Framework**: FastAPI + Uvicorn
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Search**: DuckDuckGo (free, no API key)

### Data Source

- MITRE ATT&CK knowledge base (10,000+ attack patterns)
- O-RAN architecture mapping
- Pruned STIX graph structure

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Web Interface                            │
│              (HTML/CSS/JavaScript)                           │
└────────────────┬────────────────────────────────────────────┘
                 │
      ┌──────────▼──────────┐
      │   FastAPI Backend   │
      │   (REST API)        │
      └──────────┬──────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
    ▼            ▼            ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│ RAG      │ │Vector DB │ │  Gemini  │
│ Agent    │─│ ChromaDB │─│ API      │
└──────────┘ └──────────┘ └──────────┘
    │            │
    └────────────┼─────────────────┐
                 │                 │
           ┌─────▼─────┐    ┌──────▼──────┐
           │ Embeddings │    │ Knowledge   │
           │ S-BERT     │    │ Base (JSON) │
           └────────────┘    └─────────────┘
```

## Installation

### 1. Install Dependencies

```bash
cd e:\FYP\stixx-cti

# Create/activate virtual environment
python -m venv venv
venv\Scripts\activate

# Install packages
pip install -r requirements.txt
```

### 2. Get Gemini API Key

1. Visit: https://makersuite.google.com/app/apikey
2. Sign in with Google account
3. Create API key (free tier available)
4. Copy the key

### 3. Configure Environment

Create `.env` file in the `rag/` directory:

```bash
# rag/.env
GEMINI_API_KEY=your_api_key_here
```

**Do NOT commit `.env` to version control!**

### 4. Initialize Knowledge Base

Transform graph data to RAG format:

```bash
cd rag
python data_transformer.py
```

This creates: `rag/data/threat_knowledge_base.json`

## Usage

### Quick Start

#### 1. Start the Backend API

```bash
cd rag
python api_server.py
```

Expected output:

```
🚀 Starting RAG System API Server...
   📍 Access at: http://localhost:8000
   📚 API Docs: http://localhost:8000/docs
```

#### 2. Open the Web Interface

Open `rag/frontend.html` in your browser or serve it:

```bash
# Using Python's built-in server
python -m http.server 8080 --directory rag
# Then visit http://localhost:8080/frontend.html
```

#### 3. Use the System

- **Dashboard**: View statistics and system status
- **Search**: Query the knowledge base semantically
- **Analyze Attack**: Get AI-powered threat analysis
- **Manage**: Add/edit/delete custom threats
- **Import/Export**: Backup or restore knowledge base

### Python API Usage

```python
from rag_agent import RAGAgent

# Initialize
agent = RAGAgent()

# Analyze a threat
result = agent.analyze_attack(
    attack_description="Suspicious process on Near-RT RIC with network enumeration",
    detected_indicators=["malware.exe", "odd_connections", "privilege_escalation"],
    target_component="Near-RT RIC"
)

# Generate report
report = agent.generate_report(result)
print(report)
```

### REST API Examples

#### Get System Info

```bash
curl http://localhost:8000/api/info
```

#### Search Threats

```bash
curl -X POST http://localhost:8000/api/threats/search \
  -H "Content-Type: application/json" \
  -d '{"query": "virtualization sandbox evasion", "top_k": 5}'
```

#### Analyze Attack (Async)

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "attack_description": "Unauthorized API access to O-Cloud",
    "detected_indicators": ["brute_force", "failed_auth", "suspicious_ip"],
    "target_component": "O-Cloud"
  }'
```

Result:

```json
{
  "task_id": "a1b2c3d4",
  "status": "queued",
  "message": "Analysis started. Check status with /api/analyze/a1b2c3d4"
}
```

Check result:

```bash
curl http://localhost:8000/api/analyze/a1b2c3d4
```

#### Add Custom Threat

```bash
curl -X POST http://localhost:8000/api/threats \
  -H "Content-Type: application/json" \
  -d '{
    "threat_id": "T9999_CUSTOM",
    "threat_name": "Novel Evasion Technique",
    "threat_description": "New attack pattern discovered",
    "oran_buckets": ["O-Cloud", "SMO"],
    "severity": "high"
  }'
```

## Data Format

### Knowledge Base Schema

Each threat record contains:

```json
{
  "threat_id": "T1497.001",
  "threat_name": "Virtualization/Sandbox Evasion",
  "threat_description": "Full ATT&CK description...",
  "threat_type": "attack-pattern",
  "mitre_id": "T1497.001",
  "affected_components": ["O-Cloud", "SMO"],
  "oran_buckets": ["O-Cloud", "SMO", "Near-RT RIC"],
  "evidence_terms": ["virtualization", "sandbox", "evasion"],
  "mitigations": [
    {
      "mitigation_id": "M1047",
      "mitigation_name": "Audit",
      "description": "Audit processes..."
    }
  ],
  "keywords": ["virtualization", "evasion", "detection"],
  "severity": "high",
  "created_date": "2024-01-15T10:30:00",
  "last_updated": "2024-01-15T10:30:00",
  "custom": false
}
```

### Analysis Report Format

Generated reports include:

- **Attack Information**: Description, indicators, target
- **Severity Assessment**: Low/Medium/High/Critical
- **KB Matches**: Related threats from knowledge base
- **AI Analysis**: Gemini-generated comprehensive analysis
- **Action Items**: Extracted recommendations

## File Structure

```
rag/
├── data_transformer.py          # Transform graph to threat KB
├── threat_knowledge_base.py     # ChromaDB vector store manager
├── rag_agent.py                 # RAG agent with Gemini
├── api_server.py                # FastAPI backend
├── frontend.html                # Web UI
├── .env                         # Environment variables (NOT in git)
└── data/
    ├── threat_knowledge_base.json    # Threat records
    ├── chromadb/                     # Vector database (auto-created)
    └── threat_report_*.txt           # Generated reports
```

## Key Components

### 1. DataTransformer (`data_transformer.py`)

Converts pruned STIX graph into threat records:

- Extracts attack patterns and mitigations
- Maps to O-RAN components
- Matches evidence terms
- Generates searchable keywords

**Usage:**

```python
from data_transformer import DataTransformer

transformer = DataTransformer(nodes_path, edges_path)
transformer.load_data()
transformer.transform()
transformer.save_threat_kb(output_path)
```

### 2. ThreatKnowledgeBase (`threat_knowledge_base.py`)

Manages vector store with ChromaDB:

- Semantic search using Sentence-Transformers
- CRUD operations
- Index management
- Statistics

**Usage:**

```python
from threat_knowledge_base import ThreatKnowledgeBase

kb = ThreatKnowledgeBase()
kb.index_threats()
results = kb.search_threats("sandbox evasion", top_k=5)
```

### 3. RAGAgent (`rag_agent.py`)

Retrieval-Augmented Generation pipeline:

- Searches knowledge base for relevant threats
- Generates analysis with Gemini API
- Searches internet for novel threats
- Compiles comprehensive reports

**Usage:**

```python
from rag_agent import RAGAgent

agent = RAGAgent()  # Requires GEMINI_API_KEY
result = agent.analyze_attack(
    attack_description="...",
    detected_indicators=[...],
    target_component="..."
)
```

### 4. API Server (`api_server.py`)

FastAPI REST backend:

- `/api/analyze` - Threat analysis
- `/api/threats/search` - Semantic search
- `/api/threats` - CRUD operations
- `/api/stats` - Statistics
- `/api/import/json`, `/api/export/json` - Data management

Interactive docs available at: `http://localhost:8000/docs`

## Knowledge Base Updates

### Adding Custom Threats

Option 1: Web UI

- Go to "Manage Threats" → "Add New Threat"
- Fill details and save

Option 2: API

```bash
curl -X POST http://localhost:8000/api/threats \
  -H "Content-Type: application/json" \
  -d '{...}'
```

Option 3: JSON Import

- Prepare JSON file with threat records
- Use "Import/Export" → Upload file

### Updating from Internet Search

When a novel threat is detected:

1. RAG agent searches internet
2. User reviews findings
3. Add new threat to KB via UI
4. System automatically re-indexes

## Performance & Limits

### Free Tier Limits

- **Gemini API**: 60 requests/minute (free tier)
- **ChromaDB**: Unlimited (local storage)
- **Embeddings**: Unlimited (local model)
- **Search**: Unlimited semantic queries

### Optimization Tips

- Index knowledge base once: `kb.index_threats()`
- Batch searches for better performance
- Use caching for frequent queries (TODO: implement)
- Limit top_k results to 5-10 for speed

## Troubleshooting

### Issue: "GEMINI_API_KEY not found"

**Solution:**

1. Create `.env` file in `rag/` directory
2. Add: `GEMINI_API_KEY=your_key`
3. Restart API server

### Issue: "Knowledge base not initialized"

**Solution:**

1. Run: `python data_transformer.py`
2. Verify: `rag/data/threat_knowledge_base.json` exists

### Issue: Slow semantic search

**Solution:**

1. First time loads embedding model (slow)
2. Subsequent searches are fast (cached)
3. For bulk operations, increase timeout

### Issue: ChromaDB errors

**Solution:**

1. Delete: `rag/data/chromadb/` directory
2. Run: `kb.index_threats(force_reindex=True)`

## Future Enhancements

- [ ] Query caching layer
- [ ] Multi-turn conversation with RAG
- [ ] Threat correlation across O-RAN components
- [ ] Automated threat intelligence feeds
- [ ] Role-based access control (RBAC)
- [ ] Threat feed from external CTI sources
- [ ] Machine learning models for threat scoring
- [ ] Integration with SOAR platforms

## License

This project is part of the STIXX-CTI Framework for O-RAN.

## Contact & Support

For issues, questions, or contributions:

- Create an issue in the repository
- Contact the development team

---

**Made with ❤️ for O-RAN cybersecurity**
