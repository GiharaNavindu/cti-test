FROM python:3.10-slim-bookworm

WORKDIR /code/rag

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10

COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY api_server.py .
COPY data_transformer.py .
COPY rag_agent.py .
COPY threat_knowledge_base.py .
COPY frontend.html .
COPY __init__.py .
COPY data ./data

CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]
