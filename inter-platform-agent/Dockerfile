FROM python:3.10-slim-bookworm

WORKDIR /code

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	PIP_DEFAULT_TIMEOUT=120 \
	PIP_RETRIES=10

COPY rApps/inter-platform-agent/requirements.txt ./requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
	pip install --retries 10 --timeout 120 -r requirements.txt

COPY rApps/inter-platform-agent/app /code/app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]