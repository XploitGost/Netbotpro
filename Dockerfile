FROM python:3.12-slim AS backend

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NETBOT_PROFILE=server \
    NETBOT_HOST=0.0.0.0 \
    NETBOT_PORT=8000 \
    NETBOT_RUNTIME_DIR=/var/lib/netbotpro \
    NETBOT_LOG_DIR=/var/log/netbotpro \
    NETBOT_ENABLE_LIVE_CAPTURE=false

WORKDIR /opt/netbotpro

RUN groupadd --system netbotpro && useradd --system --gid netbotpro --home-dir /var/lib/netbotpro netbotpro

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip && \
    python -m pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY core ./core
COPY config ./config
COPY agent ./agent
COPY log_manager.py core_sniffer.py ./

RUN mkdir -p /var/lib/netbotpro /var/log/netbotpro && \
    chown -R netbotpro:netbotpro /var/lib/netbotpro /var/log/netbotpro /opt/netbotpro

USER netbotpro
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import json,urllib.request; data=json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)); raise SystemExit(0 if data.get('ok') else 1)"

CMD ["python", "-m", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

