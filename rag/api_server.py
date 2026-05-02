"""
FastAPI Backend for RAG System

Provides REST API endpoints for:
- Threat analysis
- Knowledge base management (CRUD)
- Report generation
- Statistics
"""

from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from pathlib import Path
import json
import uuid
from datetime import datetime
import asyncio

# Import RAG components
from threat_knowledge_base import ThreatKnowledgeBase
from rag_agent import RAGAgent

# Initialize
app = FastAPI(title="O-RAN Threat RAG System", description="Retrieval-Augmented Generation for O-RAN threat intelligence")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
try:
    kb = ThreatKnowledgeBase()
    kb.index_threats()
    print("✓ Knowledge base initialized")
except Exception as e:
    print(f"Warning: Knowledge base initialization may have issues: {e}")
    kb = None

try:
    rag_agent = RAGAgent()
    print("✓ RAG agent initialized")
except Exception as e:
    print(f"Warning: RAG agent initialization failed: {e}")
    rag_agent = None


# Pydantic models
class ThreatAnalysisRequest(BaseModel):
    """Request model for threat analysis"""
    attack_description: str
    detected_indicators: List[str]
    target_component: Optional[str] = None


class ThreatRecord(BaseModel):
    """Threat record model"""
    threat_id: str
    threat_name: str
    threat_description: str
    threat_type: str = "attack-pattern"
    mitre_id: Optional[str] = None
    affected_components: List[str] = []
    oran_buckets: List[str] = []
    evidence_terms: List[str] = []
    mitigations: List[Dict[str, str]] = []
    keywords: List[str] = []
    severity: str = "medium"
    custom: bool = False


class ThreatSearchRequest(BaseModel):
    """Request model for threat search"""
    query: str
    top_k: int = 5


class ThreatUpdateRequest(BaseModel):
    """Request model for threat update"""
    threat_id: str
    threat_name: str
    threat_description: str
    oran_buckets: List[str] = []
    mitigations: List[Dict[str, str]] = []
    severity: str = "medium"


# Storage for async tasks
async_tasks: Dict[str, Dict[str, Any]] = {}


# ==================== HEALTH & INFO ====================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "kb_available": kb is not None,
        "rag_agent_available": rag_agent is not None,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/info")
async def system_info():
    """Get system information"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    stats = kb.get_kb_stats()
    return {
        "system": "O-RAN Threat RAG System",
        "version": "1.0.0",
        "knowledge_base": stats,
        "timestamp": datetime.now().isoformat()
    }


# ==================== THREAT ANALYSIS ====================

@app.post("/api/analyze")
async def analyze_threat(request: ThreatAnalysisRequest):
    """
    Analyze a threat and generate recommendations
    
    Waits for complete analysis before returning (synchronous response)
    """
    if not rag_agent:
        raise HTTPException(status_code=503, detail="RAG agent not initialized")
    
    try:
        print(f"\n[ANALYZE] Starting analysis...")
        result = rag_agent.analyze_attack(
            attack_description=request.attack_description,
            detected_indicators=request.detected_indicators,
            target_component=request.target_component
        )
        print(f"[ANALYZE] ✓ Analysis completed successfully")
        return {
            "status": "completed",
            "result": result
        }
    except Exception as e:
        print(f"[ANALYZE] ✗ Analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/api/analyze/{task_id}")
async def get_analysis_result(task_id: str):
    """Get analysis result by task ID"""
    if task_id not in async_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = async_tasks[task_id]
    
    if task["status"] == "processing":
        return {
            "task_id": task_id,
            "status": "processing",
            "message": "Analysis is still running. Please wait..."
        }
    
    if task["status"] == "failed":
        return {
            "task_id": task_id,
            "status": "failed",
            "error": str(task.get("error", "Unknown error"))
        }
    
    # Ensure result is JSON-serializable
    result = task.get("result", {})
    try:
        # Try to serialize and deserialize to ensure JSON compatibility
        result_json = json.loads(json.dumps(result, default=str))
    except Exception as e:
        print(f"Warning: Result serialization issue: {e}")
        result_json = {"error": "Result serialization issue", "status": "completed"}
    
    return {
        "task_id": task_id,
        "status": "completed",
        "result": result_json
    }


# ==================== KNOWLEDGE BASE SEARCH ====================

@app.post("/api/threats/search")
async def search_threats(request: ThreatSearchRequest):
    """Search threats using semantic search"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    results = kb.search_threats(request.query, top_k=request.top_k)
    
    return {
        "query": request.query,
        "total_results": len(results),
        "results": [
            {
                "threat": result["threat"],
                "relevance_score": result["relevance_score"]
            }
            for result in results
        ]
    }


@app.get("/api/threats")
async def list_threats(limit: int = 50, offset: int = 0):
    """List all threats with pagination"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    return kb.list_threats(limit=limit, offset=offset)


@app.get("/api/threats/{threat_id}")
async def get_threat(threat_id: str):
    """Get specific threat details"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    threat = kb.get_threat(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found")
    
    return threat


@app.post("/api/threats")
async def create_threat(threat: ThreatUpdateRequest):
    """Create or update threat record"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    threat_data = {
        "threat_id": threat.threat_id,
        "threat_name": threat.threat_name,
        "threat_description": threat.threat_description,
        "threat_type": "attack-pattern",
        "oran_buckets": threat.oran_buckets,
        "mitigations": threat.mitigations,
        "severity": threat.severity,
        "custom": True,
        "keywords": [threat.threat_name, *threat.oran_buckets]
    }
    
    if kb.add_threat(threat_data):
        return {
            "status": "success",
            "message": f"Threat '{threat.threat_id}' created/updated",
            "threat_id": threat.threat_id
        }
    
    raise HTTPException(status_code=400, detail="Failed to create threat")


@app.put("/api/threats/{threat_id}")
async def update_threat(threat_id: str, threat: ThreatUpdateRequest):
    """Update existing threat"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    existing = kb.get_threat(threat_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found")
    
    updated_data = existing.copy()
    updated_data.update({
        "threat_name": threat.threat_name,
        "threat_description": threat.threat_description,
        "oran_buckets": threat.oran_buckets,
        "mitigations": threat.mitigations,
        "severity": threat.severity,
    })
    
    if kb.add_threat(updated_data):
        return {
            "status": "success",
            "message": f"Threat '{threat_id}' updated",
            "threat_id": threat_id
        }
    
    raise HTTPException(status_code=400, detail="Failed to update threat")


@app.delete("/api/threats/{threat_id}")
async def delete_threat(threat_id: str):
    """Delete threat record"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    if kb.delete_threat(threat_id):
        return {
            "status": "success",
            "message": f"Threat '{threat_id}' deleted"
        }
    
    raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found")


# ==================== STATISTICS ====================

@app.get("/api/stats")
async def get_statistics():
    """Get knowledge base statistics"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    return kb.get_kb_stats()


@app.get("/api/stats/severity")
async def severity_distribution():
    """Get severity distribution"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    stats = kb.get_kb_stats()
    return stats["severity_distribution"]


@app.get("/api/stats/components")
async def components_distribution():
    """Get O-RAN components distribution"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    stats = kb.get_kb_stats()
    return {
        "total_components": stats["total_components"],
        "components": stats["components"]
    }


# ==================== IMPORT/EXPORT ====================

@app.get("/api/export/json")
async def export_knowledge_base():
    """Export entire knowledge base as JSON"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    threats = kb.list_threats(limit=10000)
    
    export_data = {
        "metadata": {
            "exported_at": datetime.now().isoformat(),
            "total_threats": threats["total"]
        },
        "threats": threats["threats"]
    }
    
    file_path = Path("rag/data") / f"kb_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(file_path, 'w') as f:
        json.dump(export_data, f, indent=2)
    
    return FileResponse(file_path, filename=file_path.name)


@app.post("/api/import/json")
async def import_threats(file: UploadFile = File(...)):
    """Import threats from JSON file"""
    if not kb:
        raise HTTPException(status_code=503, detail="Knowledge base not initialized")
    
    try:
        contents = await file.read()
        import_data = json.loads(contents)
        
        imported_count = 0
        for threat in import_data.get("threats", []):
            if kb.add_threat(threat):
                imported_count += 1
        
        return {
            "status": "success",
            "imported": imported_count,
            "message": f"Imported {imported_count} threats"
        }
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Import failed: {str(e)}")


# ==================== ROOT ====================

@app.get("/")
async def root():
    """API documentation"""
    return {
        "name": "O-RAN Threat RAG System API",
        "version": "1.0.0",
        "documentation": "/docs",
        "endpoints": {
            "health": "GET /health",
            "info": "GET /api/info",
            "analyze": "POST /api/analyze",
            "search": "POST /api/threats/search",
            "list_threats": "GET /api/threats",
            "get_threat": "GET /api/threats/{threat_id}",
            "create_threat": "POST /api/threats",
            "update_threat": "PUT /api/threats/{threat_id}",
            "delete_threat": "DELETE /api/threats/{threat_id}",
            "statistics": "GET /api/stats"
        }
    }


if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting RAG System API Server...")
    print("   📍 Access at: http://localhost:8000")
    print("   📚 API Docs: http://localhost:8000/docs")
    print("   ⏳ Server starting (loading models)...")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
