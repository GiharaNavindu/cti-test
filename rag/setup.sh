#!/bin/bash

# O-RAN Threat RAG System - Quick Setup Script for Linux/Mac

echo ""
echo "========================================"
echo "O-RAN Threat RAG System - Setup"
echo "========================================"
echo ""

# Detect if we're in WSL or have cross-platform issues
DETECTED_OS="Linux/Mac"
if grep -qi microsoft /proc/version 2>/dev/null; then
    DETECTED_OS="WSL"
    echo "[*] Detected WSL environment"
fi

# Check and remove existing venv if it's broken
if [ -d "venv" ]; then
    if [ ! -f "venv/bin/activate" ]; then
        echo "[1/4] Removing incompatible virtual environment (Windows venv detected)..."
        rm -rf venv
        echo "[1/4] Creating new virtual environment for Linux..."
        python3 -m venv venv
        if [ $? -ne 0 ]; then
            echo "Error: Failed to create virtual environment"
            exit 1
        fi
    else
        echo "[1/4] Virtual environment already exists"
    fi
else
    echo "[1/4] Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create virtual environment"
        exit 1
    fi
fi

# Activate venv
echo "[2/4] Activating virtual environment..."
if [ ! -f "venv/bin/activate" ]; then
    echo "Error: Failed to activate virtual environment (venv/bin/activate not found)"
    exit 1
fi
source venv/bin/activate

# Install dependencies with fallback for externally-managed Python
echo "[3/4] Installing dependencies..."
pip install -r requirements.txt -q 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[!] Retrying with --break-system-packages (for Debian/Ubuntu)..."
    pip install --break-system-packages -r requirements.txt -q
    if [ $? -ne 0 ]; then
        echo "Error: Failed to install dependencies"
        exit 1
    fi
fi

# Setup RAG system
echo "[4/4] Setting up RAG system..."
cd rag

# Check for .env file
if [ ! -f ".env" ]; then
    echo ""
    echo "WARNING: .env file not found!"
    echo "Please create .env file with your GEMINI_API_KEY"
    echo ""
    echo "Steps:"
    echo "  1. Visit: https://makersuite.google.com/app/apikey"
    echo "  2. Create or copy your API key"
    echo "  3. Create rag/.env file with content:"
    echo "     GEMINI_API_KEY=your_key_here"
    echo ""
fi

# Check for knowledge base
if [ ! -f "data/threat_knowledge_base.json" ]; then
    echo ""
    echo "[!] Knowledge base not found. Initializing..."
    python3 data_transformer.py
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create knowledge base"
        cd ..
        exit 1
    fi
    echo "[OK] Knowledge base initialized"
    echo ""
fi

cd ..

echo ""
echo "========================================"
echo "✓ Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo ""
echo "1. Configure Gemini API Key:"
echo "   - Create or edit: rag/.env"
echo "   - Add: GEMINI_API_KEY=your_key"
echo ""
echo "2. Start the backend API:"
echo "   $ cd rag"
echo "   $ python3 api_server.py"
echo ""
echo "3. Open web interface:"
echo "   Open: rag/frontend.html in your browser"
echo "   OR with Python server:"
echo "   $ python3 -m http.server 8080 --directory rag"
echo "   Open: http://localhost:8080/frontend.html"
echo ""
echo "4. Access API documentation:"
echo "   Open: http://localhost:8000/docs (after starting API server)"
echo ""
