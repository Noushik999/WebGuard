FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Non-root user
RUN useradd -m -u 10001 webguard

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/

# Writable dir for SQLite when no DATABASE_URL is provided
RUN mkdir -p /data && chown webguard:webguard /data
ENV DATABASE_URL=sqlite:////data/webguard.db

USER webguard
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/api/health')"

# Railway (and similar PaaS) inject a dynamic $PORT; default keeps local/docker-compose working
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --app-dir backend"]
