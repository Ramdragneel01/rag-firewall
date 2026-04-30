FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PIP_NO_CACHE_DIR=1 \
  PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install runtime deps first for better layer caching
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps .

# Run as non-root
RUN useradd --create-home --uid 10001 ragfw
USER ragfw

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3).status==200 else 1)"

CMD ["python", "-m", "rag_firewall"]
