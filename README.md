# CloudSim Studio

Visual cloud architecture simulator (Packet Tracer for cloud): design an architecture,
then check its security score, latency, availability and API behaviour.

## Architecture
    Browser -> nginx container (serves UI, proxies /api) -> FastAPI container -> SQLite on a Docker volume
    GitHub Actions: pytest + docker compose build on every push

| Cloud / DevOps piece | Where |
|---|---|
| Containers (Docker) | backend/Dockerfile, frontend/Dockerfile |
| Multi-container orchestration | docker-compose.yml (healthchecks, volume, depends_on) |
| Reverse proxy | frontend/nginx.conf |
| REST API + validation | backend/app/main.py (FastAPI + Pydantic) |
| Persistent storage | SQLite in the cloudsim-data volume |
| CI pipeline | .github/workflows/ci.yml |
| Security rules engine | backend/app/security.py |

## Backend API
| Endpoint | Purpose |
|---|---|
| POST /api/analyze | security score and findings (SEC-01..SEC-12, each tagged with an OWASP reference) |
| POST /api/simulate | routes, per-hop latency, Available / Degraded / Down |
| POST /api/request | API gateway simulation: 200, 401, 405, 429, 503 (rate limit per client) |
| GET/POST /api/architectures | save and load designs |

## Run with Docker
    docker compose up --build
    UI: http://localhost:8080     API docs: http://localhost:8000/docs

## Run tests
    cd backend && pip install -r requirements.txt && pytest

## Without Docker
Open frontend/index.html directly. The UI falls back to its in-browser engines
and shows "backend not connected".
