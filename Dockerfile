FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt pyproject.toml ./
COPY secops_core/ ./secops_core/

RUN pip install --no-cache-dir -e .

CMD ["python", "-m", "secops_core.detector"]
