![Recognyze.ai](https://github.com/recognyze-ai/traefik-bot-wall/blob/main/assets/r7e_banner_traefik.png)

# Recognyze Bot Wall Traefik Plugin

[![Go Report Card](https://goreportcard.com/badge/github.com/recognyze-ai/traefik-bot-wall)](https://goreportcard.com/report/github.com/recognyze-ai/traefik-bot-wall)
[![CI](https://github.com/recognyze-ai/traefik-bot-wall/actions/workflows/ci.yml/badge.svg)](https://github.com/recognyze-ai/traefik-bot-wall/actions/workflows/ci.yml)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/recognyze-ai/traefik-bot-wall)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/recognyze-ai/traefik-bot-wall)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/recognyze-ai/traefik-bot-wall/blob/main/LICENSE)


Yaegi middleware plugin for Traefik that enforces Recognyze botwall policy.

This repository is structured for Traefik Plugin Catalog publication:

- Plugin entry and source files at repository root
- Catalog manifest in `.traefik.yml`
- Go module in `go.mod`

For local development, use:

- `docker-compose.yaml`
- `traefik/dynamic/botwall.yml` (shared middleware example)
- `traefik/dynamic/botwall-local.yaml` (local-only override, ignored by git)
- `fixtures/`

## What this plugin does

`bot-wall` is a Traefik middleware plugin that evaluates incoming requests against Recognyze bot rules and allows or blocks traffic before it reaches your upstream service.

At a high level, the plugin:

- Resolves caller IP from proxy headers and connection data
- Loads and caches bot rules (from file and/or URL)
- Applies policy scoring/classification to decide request handling
- Optionally writes decision events to a JSONL log and publishes them to a remote endpoint

## Usage

Traefik plugins are loaded from **static configuration** at startup, then instantiated from **dynamic configuration** as middleware.

### 1) Enable the plugin in static configuration

Use local plugin mode during development:

```yaml
experimental:
  localPlugins:
    botwall:
      moduleName: github.com/recognyze-ai/traefik-bot-wall
```

For catalog/remote mode, use `experimental.plugins` with a version tag:

```yaml
experimental:
  plugins:
    botwall:
      moduleName: github.com/recognyze-ai/traefik-bot-wall
      version: v0.1.0
```

### 2) Declare middleware in dynamic configuration

Shared profile example:

```yaml
http:
  middlewares:
    r7e:
      plugin:
        botwall:
          recognyzeURL: http://host.docker.internal:8000/recognyze.txt
          allowInsecureBotRulesURL: true
          cacheTTL: 24h
          refreshBeforeExpiry: 1h
          publisherLogsURL: https://portal.recognyze.ai/api/v1/publisher/logs/
          publisherAPIKey: CHANGE_ME
```

### 3) Attach middleware to a router

```yaml
http:
  routers:
    myapp:
      rule: Host(`myapp.localhost`)
      service: myapp
      middlewares:
        - r7e
```

### 4) Choose shared vs local middleware profile

- Use `r7e@file` to run shared config from `traefik/dynamic/botwall.yml`
- Use `r7e-local@file` to run local-only config from `traefik/dynamic/botwall-local.yaml`

## Configuration

Core options used by this repository:

- `recognyzeURL`: Endpoint used by the middleware for Recognyze integration
- `botRulesFile`: Local JSON bot rules file path (bootstrap/offline scenarios)
- `botRulesURL`: Remote bot rules API URL (`disabled` to skip remote loading)
- `cacheTTL`: How long bot rules remain valid in cache
- `refreshBeforeExpiry`: How early to refresh cached rules before expiration
- `refreshJitter`: Randomized delay to avoid synchronized refreshes
- `allowInsecureBotRulesURL`: Allows `http://` endpoints for development
- `decisionLogFile`: Local JSONL path for decision/event logs
- `publisherLogsInterval`: Flush interval for publishing collected log events
- `publisherLogsURL`: Optional remote ingest endpoint for decision logs
- `publisherAPIKey`: API key sent as `X-API-KEY` when publishing logs
- `trustedProxyCIDRs`: Proxy allowlist for trusting forwarded client IP headers

References:

- Full config reference: `CONFIGURATION.md`
- Catalog validation sample: `.traefik.yml`
- Shared dynamic middleware sample: `traefik/dynamic/botwall.yml`
- Local-only middleware sample: `traefik/dynamic/botwall-local.yaml`
- Local bot rules fixture: `fixtures/botdef.json`

## Test locally

This repository already includes a local Traefik setup wired for local plugin mode.

1. Ensure your local test backend is reachable at `http://host.docker.internal:8000`.
2. Start Traefik and whoami app:
   - `docker compose up --build`
3. Send requests through Traefik:
   - `curl -H "Host: myapp.localhost" http://127.0.0.1/`
4. Inspect middleware behavior:
   - Traefik API/dashboard: `http://127.0.0.1:5051`
   - Access logs: `./logs/access.json`
   - Botwall decision logs (if enabled): `./logs/botwall_events.jsonl`
5. Iterate on plugin code and restart compose when needed.

If you want to simulate catalog conditions, tag a release and switch to `experimental.plugins` mode with that version.

## Quality gates

- CI workflow: [`.github/workflows/ci.yml`](https://github.com/recognyze-ai/traefik-bot-wall/actions/workflows/ci.yml)
- Checks on each PR and push to `main`:
  - `go test ./...`
  - [Go Report Card](https://goreportcard.com/report/github.com/recognyze-ai/traefik-bot-wall) parity (`gofmt -s`, `gocyclo` max 15) via `scripts/check-reportcard.sh`
  - `golangci-lint` (configured by `.golangci.yml`)

## Release checklist

- Ensure repository topic includes `traefik-plugin`.
- Confirm `.traefik.yml` is valid and `import` matches `go.mod` module path (`github.com/recognyze-ai/traefik-bot-wall`).
- Verify `testData` in `.traefik.yml` points to files committed in the repository.
- Run quality gates locally:
  - `go test ./...`
  - `bash scripts/check-reportcard.sh` (or `powershell -File scripts/check-reportcard.ps1` on Windows)
  - `golangci-lint run`
- Create and push a semantic version tag (for example `v0.1.0`).
- After tagging, check [GitHub Actions](https://github.com/recognyze-ai/traefik-bot-wall/actions/workflows/ci.yml) and the Traefik plugin catalog status.
