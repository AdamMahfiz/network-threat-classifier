# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    PORT=5000

# Native libs needed by scapy/matplotlib/reportlab wheels on slim images
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 libpq5 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "gunicorn==23.0.0" psycopg2-binary

COPY . .

# Non-root user; writable dirs for uploads, logs and reports
RUN useradd --create-home --uid 10001 appuser \
 && mkdir -p /app/uploads /app/logs /app/data /app/static/reports \
 && chown -R appuser:appuser /app/uploads /app/logs /app/data /app/static/reports
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','5000')+'/health', timeout=4)" || exit 1

CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
