# potzure Honeypot

Minimal Go HTTP honeypot that emulates common CMS administration paths, logs every request in structured JSON, and captures uploaded artifacts for offline analysis.

## Features

- WordPress, Joomla, and Drupal login/admin routes with believable HTML.
- Structured JSON logging (`events.log`) including headers, form data, body hash, and saved upload paths.
- Time-sliced JSON logs stored under your OS cache directory by default (override with `-log`).
- Uploads written to `uploads/` with per-file SHA256 hashes.
- Simple per-IP rate limiting to avoid resource exhaustion.
- No TLS by default; intended for use behind an isolated network sensor.

## Local Development

```bash
# Build
cd $(git rev-parse --show-toplevel)
go build ./cmd/honeypot

# Run with custom paths
./honeypot \
  -addr :8080 \
  -log ./logs/events.log \
  -uploads ./uploads \
  -id hp-edge-01
```

If `-log` is omitted the honeypot writes rotated files like
`$XDG_CACHE_HOME/potzure/events-20251130-1200.log`; otherwise the provided
path is used as the prefix for the timestamped segments. The process also
creates `uploads/` if it does not already exist.

## Container Usage

A lightweight container image is provided via the `Dockerfile` at the repository root.

```bash
# Build image
podman build -t potzure-honeypot .

# Run without outbound network access and persist logs/uploads locally
# (ensure ./logs and ./uploads exist on the host)
podman run --rm \
  --name potzure-honeypot \
  --network none \
  -p 8080:8080 \
  -v $(pwd)/events.log:/app/events.log \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/uploads:/app/uploads \
  potzure-honeypot \
    -addr :8080 -log /app/logs/events.log -uploads /app/uploads -id hp-edge-01
```

> **Isolation reminder:** deploy on an isolated VLAN or VM. Block egress at the container host firewall except for any deliberate forwarding channel to your analysis environment.

## Log Schema

Each line in `events.log` is a JSON object with the following keys:

- `timestamp`: ISO8601 time of the request.
- `src_ip`: caller IP, preferring `X-Forwarded-For` when present.
- `method`, `uri`, `headers`, `user_agent`.
- `body_hash`: SHA256 of the observed body bytes.
- `form`: parsed form values when available (login credentials, options, etc.).
- `upload_paths`: on-disk paths for captured files.
- `metadata`: auxiliary info such as HTTP status, rate-limit decisions, and upload hashes.
- `honeypot_id`: configurable identifier via `-id`.

Treat anything under `uploads/` as hostile—only analyze it within an isolated sandbox.
