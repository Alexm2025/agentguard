# syntax=docker/dockerfile:1.7
# AgentGuard image: control plane (`agentguard server run`) and gateways (`agentguard gateway ...`).
# Build with enterprise features:  docker build --build-arg WITH_EE=1 -t agentguard .

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
COPY ee ./ee
ARG WITH_EE=0
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install ".[server,gateway,ml,telemetry]" \
 && if [ "$WITH_EE" = "1" ]; then /opt/venv/bin/pip install --no-deps ./ee "authlib>=1.3" "cryptography>=42"; fi

FROM python:${PYTHON_VERSION}-slim
LABEL org.opencontainers.image.title="AgentGuard" \
      org.opencontainers.image.description="Runtime security for LLM agents" \
      org.opencontainers.image.source="https://github.com/Alexm2025/agentguard" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    AGENTGUARD_HOST=0.0.0.0 AGENTGUARD_ENV=production \
    AGENTGUARD_DATABASE_URL=sqlite+aiosqlite:////data/agentguard.db \
    AGENTGUARD_MODEL_DIR=/models/injection-classifier-v1
RUN groupadd --system --gid 10001 agentguard \
 && useradd --system --uid 10001 --gid agentguard --home-dir /nonexistent --shell /usr/sbin/nologin agentguard \
 && mkdir -p /data /models && chown agentguard:agentguard /data
COPY --from=build /opt/venv /opt/venv
USER 10001:10001
WORKDIR /data
EXPOSE 8000 8100 8200
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"AGENTGUARD_PORT\",\"8000\")}/healthz', timeout=2)"]
ENTRYPOINT ["agentguard"]
CMD ["server", "run", "--migrate"]
