# Virtlab Backend

FastAPI service for managing libvirt virtualization hosts over SSH. The API powers virtlab's guest lifecycle, console streaming, and cluster inventory features. This repository packages the app for both local development and containerized deployment.

## Features
- REST endpoints for querying libvirt hosts, guests, storage, and activity logs
- WebSocket bridge for VNC console access via SSH tunnels
- Configurable CORS and host inventory through `config.yaml`
- Containerfile targets for development (hot reload) and production images
- Taskfile helpers for Podman/buildah workflows

## Project Layout
```
config.yaml         # Example cluster + CORS configuration
Containerfile       # Multi-stage build for dev/prod images
requirements.txt    # Python dependencies
Taskfile.yml        # Common build/run automation
virt-app/           # FastAPI application package
  api/              # Route handlers (health, hosts, cluster, system_logs)
  core/             # Configuration + logging helpers
  libvirt/          # Libvirt + SSH integration layer
  main.py           # FastAPI application entrypoint
```

## Prerequisites
- Python 3.9 or newer
- libvirt headers/libraries (for local installs) or container runtime with libvirt client packages
- SSH key-based access from the API host to each libvirt hypervisor
- Optional: Podman 4.x and buildah for the provided Taskfile targets

## Configuration
Edit `config.yaml` to declare CORS rules and the libvirt hosts the API should manage:
```yaml
cors:
  allow_origins:
    - "http://localhost:5173"
    - "http://virtlab.foos.net"
  allow_credentials: true
  allow_methods: ["*"]
  allow_headers: ["*"]

hosts:
  - hostname: virt0001.foos.net
    user: admin
    ssh:
      known_hosts_verify: ignore
```
Place SSH material for the `user` accounts under `.ssh/` (ignored by git). The default container setup mounts this directory at `/home/virt/.ssh`.

Environment variables override key settings:
- `CONFIG_FILE` – alternate path to the YAML config
- `LOG_LEVEL` – Python logging level (default `INFO`)
- `APP_NAME`, `APP_VERSION` – metadata surfaced on `/`

## Local Development
```bash
python -m venv .venv              # or: task env:bootstrap
source .venv/bin/activate
pip install -r requirements.txt   # task env:bootstrap runs this automatically
export CONFIG_FILE=$(pwd)/config.yaml
uvicorn virt-app.app.main:app --reload --host 0.0.0.0 --port 8000
```
Run these commands from the repository root so `uvicorn` can import the `virt-app` package. If you prefer the Taskfile helper, execute `task env:bootstrap` once to create `.venv` and install dependencies before launching the app. Visit `http://localhost:8000/docs` for interactive OpenAPI docs. The frontend defaults to `http://localhost:8000` when using the dev container.

### Database Migrations
Set `DATABASE_URL` (defaults to `postgresql+asyncpg://postgres:postgres@localhost:5432/virtlab`) before invoking the migration helpers below. New revisions reflect the ORM models under `virt-app/db/models`.

- `task db:check` – run a quick async connectivity check using the configured database URL
- `task db:upgrade` – apply migrations up to the requested target (defaults to `head`)
- `task db:downgrade` – roll back the schema by one revision or to a provided target
- `task db:revision MESSAGE="add widgets"` – autogenerate a revision after updating ORM models

#### Dev PostgreSQL
Spin up a local database with Podman and have it persist data under `.data/postgres`:

- `task db:dev:up` – launch PostgreSQL (default image `postgres:16` on port `5433`)
- `task db:dev:down` – stop and remove the container
- `task db:dev:logs` – stream server logs
- `task db:dev:psql` – open a psql shell inside the container

By default the instance exposes `DATABASE_URL=postgresql+asyncpg://virtlab:virtlab@localhost:5433/virtlab`. The Taskfile falls back to this URL for `task db:check` if `DATABASE_URL` is unset. Adjust credentials or ports via Task variables (e.g., `task db:dev:up DB_PORT=5544`).

### Storage & Network Schema
- `storage_domains` capture libvirt pools (shared or host-local) with extra driver metadata. Shared pools deduplicate on name/type; local pools fan out via host status records.
- `host_storage_status` tracks each host's availability for a given domain, including capacity metrics and health state.
- `networks` normalize libvirt network definitions (bridge, VLAN, forward mode) with optional shared flags.
- `host_network_status` records per-host network state (active/inactive/missing) and operational details such as bridge activity.

Run `go-task db:revision MESSAGE="storage topology"` after you adjust the ORM models, then `go-task db:upgrade` to apply the schema changes.

### Storage APIs
- `GET /api/cluster/storage` – legacy per-host inventory plus a `storage_domains` array sourced from the database (each entry includes host summaries).
- `GET /api/storage/{uuid}` – detailed view for a single storage domain showing host mount status and capacity metrics.

### Tests & Linting
Run the project's test suite (once available) with `pytest`. Ensure any new libvirt interactions are covered by unit or integration tests before pushing changes.

## Container Workflows
The `Taskfile.yml` wraps common Podman/buildah operations:

- `task build` – build the production image (`prod` stage)
- `task up` – run the containerized API on `http://localhost:8000`
- `task logs` – follow container logs
- `task dev:up` – start the dev image with code mounted for live reload

All container targets expect an `.ssh/` directory alongside the Taskfile. Podman volumes map it into the container for outbound tunnels.

## Deployment Notes
- Ensure the runtime host has passwordless SSH access to each hypervisor (keys + known_hosts)
- Expose port 8000 (or your chosen mapping) through your reverse proxy; the root `nginx-reverse-proxy.conf` routes `/api` and `/ws` to this service
- Keep secrets (SSH keys, configs with credentials) outside version control; `.ssh/` is gitignored by default
- Run `pytest` (and any integration checks you add) before opening a PR, and document smoke tests per repo guidelines

## Support & Troubleshooting
- `podman logs virtlab-backend` (or `virtlab-backend-dev`) shows API logs with tunnel + libvirt diagnostics
- The activity log endpoints capture console/VNC events for debugging session setup
- If SSH tunnels stall, verify the key permissions and adjust `ssh` options in `config.yaml`
