# O-RAN Threat RAG System - Quick Start Guide

Get the RAG system up and running in 5 minutes!

## Prerequisites

- Python 3.8+
- Windows, Linux, or macOS
- Internet connection (for downloading models and Gemini API)
- Google account (for Gemini API key)

## Step 1: Get Gemini API Key (2 minutes)

1. Visit: https://makersuite.google.com/app/apikey
2. Click "Create API key"
3. Copy the key to clipboard
4. **Keep it safe!** (Don't share or commit to git)

## Step 2: Run Setup Script (2 minutes)

### Windows

```cmd
cd e:\FYP\stixx-cti
rag\setup.bat
```

### Linux/Mac

```bash
cd ~/FYP/stixx-cti
chmod +x rag/setup.sh
rag/setup.sh
```

This will:

- Create virtual environment
- Install all dependencies
- Initialize knowledge base
- Create necessary directories

## Step 3: Configure API Key (1 minute)

Create file: `rag/.env`

```env
GEMINI_API_KEY=your_key_from_step_1_here
```

**Windows example:**

```
e:\FYP\stixx-cti\rag\.env
```

## Step 4: Start API Server (Immediately!)

```bash
cd rag
python api_server.py
```

You should see:

```
🚀 Starting RAG System API Server...
   📍 Access at: http://localhost:8000
   📚 API Docs: http://localhost:8000/docs
```

**Keep this terminal open!**

## Step 5: Open Web Interface

Open in your browser:

```
rag/frontend.html
```

Or with a simple HTTP server:

```bash
# In a new terminal, in rag/ directory
python -m http.server 8080
```

Then open: `http://localhost:8080/frontend.html`

---

## That's it! You're ready to use the RAG system 🎉

### What you can do now:

1. **📊 Dashboard**: View threat statistics and system status
2. **🔍 Search**: Search threats semantically
   - Example: "detect sandbox evasion"
3. **⚠️ Analyze**: Analyze attacks with AI
   - Example: "Found suspicious process on Near-RT RIC"
4. **📝 Manage**: Add custom threats
5. **📤 Export**: Backup knowledge base

---

## Common Commands

### Test the API

```bash
# Check health
curl http://localhost:8000/health

# Get info
curl http://localhost:8000/api/info

# Search threats
curl -X POST http://localhost:8000/api/threats/search \
  -H "Content-Type: application/json" \
  -d '{"query":"O-Cloud virtualization","top_k":5}'
```

### Use RAG Agent Directly

```python
from rag.rag_agent import RAGAgent

agent = RAGAgent()

# Analyze attack
result = agent.analyze_attack(
    attack_description="Crypto mining detected on O-DU",
    detected_indicators=["suspicious_process", "high_cpu"],
    target_component="O-DU"
)

# Print report
print(agent.generate_report(result))
```

---

## Troubleshooting

### ❌ "ImportError: No module named 'google'"

**Fix:** Reinstall dependencies

```bash
pip install -r requirements.txt
```

### ❌ "GEMINI_API_KEY not found"

**Fix:** Create `.env` file in `rag/` directory with your key

### ❌ "Knowledge base not initialized"

**Fix:** Initialize it

```bash
cd rag
python data_transformer.py
```

### ❌ API won't start

**Fix:** Check if port 8000 is in use

```bash
# Windows
netstat -ano | findstr :8000

# Linux/Mac
lsof -i :8000
```

---

## Next Steps

1. **Read the full README**: `rag/README.md`
2. **Explore API docs**: `http://localhost:8000/docs`
3. **Add custom threats**: Use web UI → Manage Threats
4. **Analyze real attacks**: Use Analyze Attack feature
5. **Export knowledge base**: For backup/sharing

---

## Architecture Overview

```
You (Web Browser)
    ↓
frontend.html (your interface)
    ↓
FastAPI Server (localhost:8000)
    ↓
    ├→ RAG Agent (AI analysis)
    │   ├→ ChromaDB (vector search)
    │   └→ Gemini API (LLM)
    ├→ Threat Knowledge Base
    │   └→ 10,000+ threats
    └→ Statistics & Management
```

---

## Cost Breakdown

| Component             | Cost                   |
| --------------------- | ---------------------- |
| ChromaDB              | Free (local)           |
| Sentence-Transformers | Free (local)           |
| Gemini API            | Free (60 req/min tier) |
| FastAPI               | Free (open-source)     |
| **Total**             | **$0** ✓               |

---

## Support

Having issues? Check:

1. `rag/README.md` - Full documentation
2. `http://localhost:8000/docs` - API documentation
3. Terminal output for error messages

---

## Quick Reference

| Action        | Command                                                     |
| ------------- | ----------------------------------------------------------- |
| Start API     | `python rag/api_server.py`                                  |
| Reindex KB    | `python rag/api_server.py` then call `/api/threats/reindex` |
| Export KB     | Web UI → Import/Export → Export KB                          |
| Import KB     | Web UI → Import/Export → Select file → Import KB            |
| View API docs | Visit `http://localhost:8000/docs`                          |

---

Happy threat hunting! 🛡️
