# reload-push-options Test Suite

Integration tests for the `reload-push-options` management command.

## Prerequisites

- Docker & Docker Compose
- OpenSSL (for key generation)

## Quick Start

```bash
cd tests/reload_push_options
./run.sh
```

## What it tests

| Test | Description |
|------|-------------|
| 1 | Basic reload without update-clients - existing clients unchanged |
| 2 | Update clients with new route added |
| 3 | Update clients with route removed |
| 4 | Update clients with all routes removed |
| 5 | Update clients with only new routes (complete replacement) |
| 6 | Update clients with mixed changes (add + remove) |
| 7 | New client receives updated config |
| 8 | Stress test with 500 routes |

## Architecture

```
┌─────────────────────────────────────────────────┐
│                Docker Network                   │
│                 10.100.0.0/24                   │
│                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐   │
│  │  Server  │    │ Client1  │    │ Client2  │   │
│  │ .0.2     │◄───│ .0.10    │    │ .0.11    │   │
│  │          │◄───│          │    │          │   │
│  │ :7505    │    │          │    │          │   │
│  │ (mgmt)   │    │          │    │          │   │
│  └──────────┘    └──────────┘    └──────────┘   │
│       │                                         │
└───────┼─────────────────────────────────────────┘
        │
   localhost:7505 (management interface)
```

## Manual Testing

```bash
# Start the environment
docker compose up -d

# Connect to management interface
nc localhost 7505

# Commands to try:
help
status
reload-push-options
reload-push-options update-clients
```

## Files

- `docker-compose.yml` - Container orchestration
- `Dockerfile` - Builds OpenVPN from source
- `configs/server.conf.default` - Default server config (baked into image)
- `configs/client.conf` - Client config
- `keys/` - PKI (auto-generated)
- `scripts/` - Entrypoints and helpers
- `results/` - Test output and logs

## How Config Updates Work

1. Default server config (`server.conf.default`) is copied into the Docker image
2. On container start, `server-entrypoint.sh` restores it to `/etc/openvpn/server.conf`
3. During tests, config is updated inside the container via `docker compose exec`
4. This ensures each test run starts from a clean, known state



