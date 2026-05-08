# Recognyze Botwall Traefik Setup

## Quick start

1. Start the stack:
   - `docker compose -f docker-compose.yaml up -d`
2. Send traffic through Traefik:
   - `curl -H "Host: myapp.localhost" http://localhost/`
3. Open Traefik dashboard:
   - `http://localhost:5051/dashboard/`
4. Check decision events:
   - `docker exec traefik-r7e sh -lc "tail -n 20 /var/log/traefik/botwall_events.jsonl"`

## Current local routing

- Traefik web entrypoint is exposed on host port `80`.
- Traefik dashboard is exposed on host port `5051`.
- Router rule matches host `myapp.localhost`.
- Middleware is attached as `r7e@file`.
- Upstream service points to `http://host.docker.internal:8000`.
- Do not point upstream to `localhost:7070`, or you will create a proxy loop.

## Middleware config source

- Middleware definition lives in `traefik/dynamic/botwall.yml`.
- Traefik loads it via file provider:
  - `--providers.file.directory=/etc/traefik/dynamic`
  - `--providers.file.watch=true`

## Config behavior

- `recognyzeURL` takes precedence when configured.
- If `recognyzeURL` is empty, plugin discovers through `robots.txt` `Recognyze:` directive.
- `botRulesFile` is optional.
- If `botRulesFile` is empty or unreadable, plugin falls back to embedded default bot rules.
- `cacheTTL` default is `24h`.
- `refreshBeforeExpiry` default is `1h` (refresh starts at hour 23).
- Set `publisherLogsURL` (e.g. `https://portal.dev.recognyze.ai/api/v1/publisher/logs/`) and `publisherAPIKey` to ship decision events to the Recognyze portal. The plugin POSTs the JSONL file body as `application/jsonl` with header `X-API-KEY: <publisherAPIKey>`; on HTTP 2xx the file is truncated.
- Full configuration reference (all keys, defaults, and examples): `CONFIGURATION.md`.

## 403 contract

- Status: `403`
- Headers:
  - `Content-Type: text/plain; charset=utf-8`
  - `X-Robots-Tag: noindex, nofollow`
  - `Cache-Control: no-cache, no-store, must-revalidate`
  - `Pragma: no-cache`
  - `Expires: 0`
- Body:
  - `Automated tools are only permitted to access this page if registered with the site operator.`



Access Logs

docker exec traefik-r7e sh -lc "tail -n 20 /var/log/traefik/access.json"



## Commands

# 1) Copy logs from Traefik container to local
docker compose cp traefik:/var/log/traefik/botwall_events.jsonl ./logs/traefik/botwall_events.jsonl
docker compose cp traefik:/var/log/traefik/botwall_events.meta.json ./logs/traefik/botwall_events.meta.json
