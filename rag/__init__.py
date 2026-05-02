"""
O-RAN Threat RAG System

A comprehensive Retrieval-Augmented Generation system for O-RAN cybersecurity threat intelligence.
Combines semantic search with Google Gemini AI to analyze threats and provide mitigation strategies.

Components:
- data_transformer: Convert STIX graph data to threat knowledge base
- threat_knowledge_base: ChromaDB-backed vector store for semantic search
- rag_agent: RAG pipeline with Gemini AI
- api_server: FastAPI REST backend
- frontend: Web interface for KB management and threat analysis
"""

__version__ = "1.0.0"
__author__ = "STIXX-CTI Team"
__description__ = "Retrieval-Augmented Generation for O-RAN Threat Intelligence"

try:
    from .threat_knowledge_base import ThreatKnowledgeBase
    from .rag_agent import RAGAgent
    from .data_transformer import DataTransformer
except ImportError:
    pass  # Package may be used as CLI without importing

__all__ = [
    "ThreatKnowledgeBase",
    "RAGAgent",
    "DataTransformer",
]
