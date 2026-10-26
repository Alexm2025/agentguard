# Deployment

## Docker

```bash
docker build -t agentguard .                       # add --build-arg WITH_EE=1 for enterprise features
docker run -p 8000:8000 -e AGENTGUARD_SECRET_KEY=... -v agdata:/data agentguard            # control plane
docker run -p 8200:8200 agentguard gateway llm --host 0.0.0.0 --config /config/gateway.yaml
```

The image runs as UID 10001, works with a read-only root filesystem (`/data` and `/tmp` writable),
and has a `/healthz` health check. CI verifies the non-root user and the health endpoint on every
push.

## docker compose (full stack)

```bash
cp deploy/.env.example deploy/.env      # set every secret
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
```

Runs the control plane, LLM gateway and MCP gateway with Postgres 16 and Redis 7. Containers drop
all capabilities, set `no-new-privileges` and use read-only filesystems. Mount the classifier at
`./models/injection-classifier-v1` to enable the ML layer.

## Kubernetes (Helm)

```bash
kubectl create secret generic agentguard \
  --from-literal=database-url='postgresql+psycopg://…' --from-literal=redis-url='redis://…' \
  --from-literal=secret-key="$(openssl rand -base64 48)" --from-literal=service-token="$(openssl rand -hex 32)" \
  --from-literal=gateway-api-key='ag_live_…'
helm install agentguard deploy/helm/agentguard --set publicUrl=https://agentguard.example.com \
  --set ingress.enabled=true --set ingress.host=agentguard.example.com
```

- Migrations run in a `pre-install` / `pre-upgrade` hook Job, so replicas never race.
- Pods: non-root, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, no
  service-account token.
- The LLM gateway is stateless: scale with replicas, `llmGateway.workers` and the HPA.
- The MCP gateway keeps per-session taint state in memory; its Service uses
  `sessionAffinity: ClientIP`. Keep `mcpGateway.replicas: 1` unless clients keep stable IPs.

## Public demo on Render

`render.yaml` is a blueprint for a free demo instance: **New → Blueprint → this repository**, then
set the admin password. It runs migrations, starts the server and loads demo sessions
(`agentguard server seed-demo`). Free instances have no persistent disk, so the demo database
resets on restart.

## TLS

Terminate TLS at your ingress or load balancer, or pass `--ssl-certfile` / `--ssl-keyfile`
(`AGENTGUARD_TLS_CERT` / `AGENTGUARD_TLS_KEY`). With `AGENTGUARD_ENV=production` or an `https://`
public URL, cookies are `Secure` and HSTS is sent. Set `AGENTGUARD_TRUST_PROXY_HEADERS=true` only
behind a proxy you control.

## Upgrades and backups

- `agentguard server migrate` is idempotent; run it (or the Helm hook) before starting a new version.
- Back up Postgres. Export the audit log (`/api/v1/audit/export`) or ship its head hash to your SIEM
  so truncation is detectable.
- `agentguard server prune` enforces event retention (`AGENTGUARD_EVENT_RETENTION_DAYS`).
