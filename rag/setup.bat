@echo off
REM O-RAN Threat RAG System - Quick Setup Script for Windows

echo.
echo ========================================
echo O-RAN Threat RAG System - Setup
echo ========================================
echo.

REM Check if venv exists and is valid
if exist "venv\Scripts\pip.exe" (
    echo [1/4] Virtual environment already exists and is valid
) else (
    if exist "venv" (
        echo [1/4] Removing corrupted/incompatible virtual environment...
        rmdir /s /q venv >nul 2>&1
    )
    echo [1/4] Creating new virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo Error: Failed to create virtual environment
        exit /b 1
    )
)

REM Activate venv
echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo [3/4] Installing dependencies...
python -m pip install --upgrade pip -q
if errorlevel 1 (
    echo Warning: pip upgrade failed, continuing...
)
pip install -r requirements.txt -q
if errorlevel 1 (
    echo Error: Failed to install dependencies
    exit /b 1
)

REM Setup RAG system
echo [4/4] Setting up RAG system...
cd rag

REM Check for .env file
if not exist ".env" (
    echo.
    echo WARNING: .env file not found!
    echo Please create .env file with your GEMINI_API_KEY
    echo.
    echo Steps:
    echo   1. Visit: https://makersuite.google.com/app/apikey
    echo   2. Create or copy your API key
    echo   3. Create rag\.env file with content:
    echo      GEMINI_API_KEY=your_key_here
    echo.
)

REM Check for knowledge base
if not exist "data\threat_knowledge_base.json" (
    echo.
    echo [!] Knowledge base not found. Initializing...
    python data_transformer.py
    if errorlevel 1 (
        echo Error: Failed to create knowledge base
        cd ..
        exit /b 1
    )
    echo [OK] Knowledge base initialized
    echo.
)

cd ..

echo.
echo ========================================
echo ✓ Setup Complete!
echo ========================================
echo.
echo Next steps:
echo.
echo 1. Configure Gemini API Key:
echo    - Create or edit: rag\.env
echo    - Add: GEMINI_API_KEY=your_key
echo.
echo 2. Start the backend API:
echo    run: cd rag
echo    run: python api_server.py
echo.
echo 3. Open web interface:
echo    Open: rag/frontend.html in your browser
echo    OR with Python server:
echo    run: python -m http.server 8080 --directory rag
echo    Open: http://localhost:8080/frontend.html
echo.
echo 4. Access API documentation:
echo    Open: http://localhost:8000/docs (after starting API server)
echo.
pause
