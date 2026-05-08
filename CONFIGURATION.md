# botwall Configuration Guide

This guide documents all middleware settings, where to configure them, and how they affect runtime behavior.

## Where to configure settings

Use one of these Traefik configuration patterns:

- File provider (dynamic config, current local setup): `http.middlewares.<name>.plugin.botwall:`
- Docker label (legacy/optional): `traefik.http.middlewares.<name>.plugin.botwall=...`
- Plugin `testData` in `.traefik.yml` (for Traefik plugin metadata/catalog test runs only, not production runtime config).

In this repository, the active local configuration is in:

- `traefik/dynamic/botwall.yml` (middleware definition)
- referenced by `docker-compose.yaml` through:
  - `--providers.file.directory=/etc/traefik/dynamic`
  - `--providers.file.watch=true` (reload when YAML files in that directory change)
  - In this repo’s `docker-compose.yaml`, the sample app uses `traefik.http.routers.myapp.middlewares=r7e@file`.

## Current local routing (dev setup)

- Traefik web entrypoint is exposed on host port `80` (for example `http://localhost/`).
- Traefik dashboard is exposed at `http://localhost:5051/dashboard/`.
- The sample `myapp` router matches host `myapp.localhost`.
- Upstream target in that sample is `http://host.docker.internal:8000`.
- If your browser cannot resolve `myapp.localhost`, add a hosts entry:
  - `127.0.0.1 myapp.localhost`

## Default bot rules baseline (recommended default)

The plugin ships a portable default bot rules payload in `defaultBotDef.json`.

- If `botRulesFile` is empty, the plugin loads `defaultBotDef.json` at startup (`default_file` source).
- If `botRulesFile` is set and readable, it overrides the default file (`local_file` source).
- If `botRulesFile` is set but unreadable, the plugin logs a warning and keeps the baseline defaults already loaded from `defaultBotDef.json`.
- If **`botRulesURL` is enabled** (omitted → defaults to prod; **`disabled`** / **`none`** / **`off`** → no remote sync) and `rulesCacheFile` is readable, cached remote rules are used only when cache is not older than `botRulesFile` (unless `preferLocalBotRulesFile: true`).
- On successful remote refresh, remote rules are persisted to `rulesCacheFile` and also to `botRulesFile` when configured.

## Full settings reference

All keys are JSON/YAML fields on the plugin config object.

| Key | Default | Required | Purpose |
| --- | --- | --- | --- |
| `recognyzeURL` | empty | No | Absolute URL to `recognyze.txt` protected-path list. If set, it has discovery priority over `robots.txt`. |
| `robotsTxtURL` | empty | No | Optional explicit `robots.txt` URL for discovery fallback. If empty, plugin uses `<request-scheme>://<host>/robots.txt`. |
| `cacheTTL` | `24h` | No | Lifetime of protected-path snapshot cache. Must be valid Go duration (`time.ParseDuration` format). |
| `refreshBeforeExpiry` | `1h` | No | How early protected-path refresh starts before cache expiry. Must be lower than `cacheTTL`. |
| `refreshJitter` | `5m` | No | Random jitter added to protected-path refresh scheduling. |
| `cacheFile` | `/tmp/botwall_recognyze_cache.json` | No | File path where protected-path cache state is persisted. |
| `botRulesFile` | empty | No | Optional local bot-rules JSON file. It overrides `defaultBotDef.json` at startup; when remote sync is enabled, successful remote refresh also updates this file. |
| `botRulesURL` | `https://portal.recognyze.ai/api/v1/bot-rules` (applied when omitted; production [Bot Rules API](https://portal.recognyze.ai/api/v1/bot-rules)) | No | Override for other environments, e.g. dev `https://portal.dev.recognyze.ai/api/v1/bot-rules`. Set to `disabled`, `none`, or `off` to disable remote sync (`http://` URLs require `allowInsecureBotRulesURL`). |
| `preferLocalBotRulesFile` | `false` | No | Startup precedence toggle. When `true` and `botRulesFile` is present, local rules are kept even if `rulesCacheFile` is newer. |
| `allowInsecureBotRulesURL` | `false` | No | Dev-only escape hatch to allow `http://` values for `botRulesURL`. Avoid in production; traffic can be intercepted/tampered. |
| `rulesRefreshInterval` | `6h` | No | Interval between remote bot-rules refresh attempts when `botRulesURL` is set. |
| `rulesMergeStrategy` | `replace-with-remote-on-success` | No | Remote rule apply behavior. `merge` merges remote over current; any other value replaces with remote snapshot. |
| `rulesCacheFile` | `/tmp/botwall_rules_cache.json` | No | File path for persisted remote bot-rules snapshot. It is considered at startup only when `botRulesURL` is set and cache is not older than `botRulesFile`. |
| `denyInfoURL` | (empty; runtime falls back to `https://www.recognyze.ai/aggregators`) | No | URL embedded in the 403 deny body. Set this to your own controlled documentation page to avoid dependency on third-party domain ownership changes. |
| `decisionLogFile` | `/var/log/traefik/botwall_events.jsonl` | No | JSONL file path for decision logging (`blocked_visit`, `signed_visit`). The logger may prepend a one-line export metadata object; see “Decision log and event shipping” below. |
| `publisherLogsURL` | empty | No | Optional absolute URL to the Recognyze publisher logs ingest endpoint (production: `https://portal.recognyze.ai/api/v1/publisher/logs/`, dev: `https://portal.dev.recognyze.ai/api/v1/publisher/logs/`). When set, the plugin POSTs the decision JSONL file body as `application/jsonl` (one `AccessLogEvent` JSON object per line) authenticated with the `X-API-KEY: <publisherAPIKey>` header, and, after a successful response, truncates the log file. Must be `https://` by default; `http://` is allowed only when `allowInsecureBotRulesURL: true` (dev). |
| `publisherAPIKey` | empty | Yes when `publisherLogsURL` is set | Plaintext API key sent in the `X-API-KEY` header to `publisherLogsURL`. Startup fails if `publisherLogsURL` is set but this is empty. The key sits in the YAML file in plaintext — protect the file with filesystem permissions or Docker/Kubernetes secrets. |
| `publisherLogsInterval` | `5m` | No | How often the background ship loop runs when `publisherLogsURL` is set, and the minimum interval between on-write ship attempts. Must be a valid Go duration and greater than `0`. |
| `policy.globalPolicy` | `deny` | No | Default policy when category path has no explicit rule (`allow` or `deny`). |
| `policy.rules` | `{}` | No | Category policy map (`<category-path>` -> `allow`/`deny`). Longest-prefix match is applied. |
| `policy.botOverrides` | `{}` | No | Per-bot overrides (`<bot-slug>` -> `allow`/`deny`) applied after category decision. |
| `trustedProxyCIDRs` | empty | No | CIDRs (or bare IPs) for **trusted immediate TCP peers** (`RemoteAddr`). When non-empty, `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Real-IP` are honored **only** if the peer IP falls in one of these networks; otherwise those headers are ignored and the client IP is taken from `RemoteAddr` (spoof-resistant). When empty, legacy behavior applies: forwarded headers may still be used (see validation notes). |
| `enableIPSoftmax` | `false` | No | When `true` and bot rules include `ipVerification.bots` with IP ranges, enable UA+IP **softmax** attribution and anti-spoof gates (see `ARCHITECTURE.md`). |
| `softmaxAlpha` | `4` | No | Weight on UA match in softmax (must be `> 0`; values `<= 0` normalize to `4`). |
| `softmaxBeta` | `4` | No | Weight on IP-in-range match in softmax (must be `> 0`; values `<= 0` normalize to `4`). |

## `botRulesURL`

`botRulesURL` is the Recognyze **Bot Rules API** URL used for remote sync. If you omit it, the plugin uses the production default from the settings table. Override it for other environments (for example a dev portal base under `/api/v1/bot-rules`). Use `disabled`, `none`, or `off` to turn off remote fetch.

Example: `https://your-portal.example/api/v1/bot-rules`

## Docker label example (alternative)

Use a single JSON object in the label value:

```yaml
labels:
  - 'traefik.http.middlewares.r7e.plugin.botwall={
      "botRulesFile":"/fixtures/botdef.json",
      "botRulesURL":"https://your-portal.example/api/v1/bot-rules",
      "preferLocalBotRulesFile":true,
      "rulesRefreshInterval":"6h",
      "rulesMergeStrategy":"replace-with-remote-on-success",
      "recognyzeURL":"https://your-site.example/recognyze.txt",
      "cacheTTL":"24h",
      "refreshBeforeExpiry":"1h",
      "refreshJitter":"5m",
      "cacheFile":"/tmp/botwall_recognyze_cache.json",
      "rulesCacheFile":"/tmp/botwall_rules_cache.json",
      "decisionLogFile":"/var/log/traefik/botwall_events.jsonl",
      "publisherLogsURL":"https://portal.dev.recognyze.ai/api/v1/publisher/logs/",
      "publisherAPIKey":"REPLACE_ME",
      "publisherLogsInterval":"5m",
      "policy":{
        "globalPolicy":"deny",
        "rules":{
          "traditional/bots":"deny",
          "ai/access_agents":"allow",
          "ai/data_scrapers":"deny"
        },
        "botOverrides":{
          "googlebot":"allow"
        }
      }
    }'
```

Tip: the example above is multiline for readability. In `docker-compose.yaml`, you can keep the JSON compact in one line if preferred.

## File provider YAML example

This repository’s checked-in `traefik/dynamic/botwall.yml` points `recognyzeURL` at a local upstream, enables `allowInsecureBotRulesURL` (so `http://` URLs are allowed in dev), sets `decisionLogFile`, and demonstrates optional `publisherLogsURL` / `publisherAPIKey` / `publisherLogsInterval` for shipping decision events to the Recognyze portal. Comments show optional `botRulesURL` (dev portal) and `trustedProxyCIDRs`. Omitted `botRulesURL` defaults to production `https://portal.recognyze.ai/api/v1/bot-rules` (see table above). It does not set `botRulesFile`, so embedded default bot rules apply until the first successful remote refresh.

Minimal example (embedded bot rules, protected paths only):

```yaml
http:
  middlewares:
    r7e:
      plugin:
        botwall:
          recognyzeURL: https://<your-site>/recognyze.txt
          cacheTTL: 24h
          refreshBeforeExpiry: 1h
```

A fuller example (typical for staging/production) might look like this:

```yaml
http:
  middlewares:
    r7e:
      plugin:
        botwall:
          # Optional: only set this when you need an operator-managed override on disk
          # botRulesFile: /data/botdef.json
          # preferLocalBotRulesFile: true
          botRulesURL: https://your-portal.example/api/v1/bot-rules
          rulesRefreshInterval: 6h
          rulesMergeStrategy: replace-with-remote-on-success
          recognyzeURL: https://your-site.example/recognyze.txt
          cacheTTL: 24h
          refreshBeforeExpiry: 1h
          refreshJitter: 5m
          cacheFile: /tmp/botwall_recognyze_cache.json
          rulesCacheFile: /tmp/botwall_rules_cache.json
          decisionLogFile: /var/log/traefik/botwall_events.jsonl
          publisherLogsURL: https://portal.dev.recognyze.ai/api/v1/publisher/logs/
          publisherAPIKey: REPLACE_ME
          publisherLogsInterval: 5m
          policy:
            globalPolicy: deny
            rules:
              traditional/bots: deny
              ai/access_agents: allow
              ai/data_scrapers: deny
            botOverrides:
              googlebot: allow
```

## Validation notes

- Duration fields must be valid Go duration strings (for example: `30s`, `5m`, `1h`, `24h`).
- `refreshBeforeExpiry` must be smaller than `cacheTTL`.
- `policy` values normalize to `allow` or `deny`; invalid values fall back to defaults.
- If `botRulesFile` is empty, the plugin loads `defaultBotDef.json` defaults.
- If `botRulesFile` is unreadable, the plugin logs a warning and keeps defaults already loaded from `defaultBotDef.json`.
- If `botRulesURL` is omitted, it defaults to `https://portal.recognyze.ai/api/v1/bot-rules`. Set to `disabled` / `none` / `off` to disable remote bot-rules sync and rely on `defaultBotDef.json`, `botRulesFile`, and/or cache only.
- If `botRulesURL` is set and both `botRulesFile` and `rulesCacheFile` are present, cache wins only when it is not older than local; set `preferLocalBotRulesFile: true` to force local precedence.
- `botRulesURL` must use `https://` unless `allowInsecureBotRulesURL: true` is explicitly set for development environments.
- `botRulesFile` and `rulesCacheFile` are operator-provided filesystem paths. Treat plugin config as privileged input and restrict who can modify Traefik/plugin configuration.
- **Client IP:** the resolved address is stored in the access event as `remote_logname` (Apache combined–style field). Resolution order: if `trustedProxyCIDRs` is set, only trust forwarded headers when the TCP peer is in those CIDRs; otherwise use `RemoteAddr`. If `trustedProxyCIDRs` is empty, headers `CF-Connecting-IP` → `X-Forwarded-For` (first parseable hop) → `X-Real-IP` are still consulted for compatibility (treat as untrusted for access-control decisions unless you configure `trustedProxyCIDRs`).
- **IP verification / softmax:** when remote bot rules include `ipVerification.bots` (from the portal JSON) and `enableIPSoftmax: true`, the plugin applies UA+IP softmax and anti-spoof rules (winner must match published IP ranges when ranges exist; legacy UA-only claims can be denied). With `enableIPSoftmax: false`, classification is UA/category-based only; IP lists in rules are not used for enforcement.
- `publisherLogsURL` must be `https://` unless `allowInsecureBotRulesURL: true` (same dev escape hatch as `botRulesURL`).
- `publisherAPIKey` is required when `publisherLogsURL` is set; startup fails fast otherwise (the plugin never ships unauthenticated).
- `publisherLogsInterval` must be greater than `0` (for example `1m`, `5m`).

## Decision log and publisher logs shipping

When `decisionLogFile` is set, each decision appends one JSON object per line. The first line of the file may be a **metadata** envelope when the file is new or migrated; event lines follow.

If `publisherLogsURL` is set, `publisherAPIKey` is set, and `publisherLogsInterval` is valid:

- A **background loop** runs at `publisherLogsInterval` and calls the ship routine.
- On each append, if enough time has passed since the last ship, the plugin may also ship in the background after the write.
- The shipped request is `POST {publisherLogsURL}` with headers `Content-Type: application/jsonl`, `Accept: application/json`, and `X-API-KEY: <publisherAPIKey>`. The body is the current contents of the JSONL file (metadata envelope first line followed by one `AccessLogEvent` per line).
- The portal accepts the shipped `application/jsonl` body and an alternative single JSON array payload with the same `AccessLogEvent` schema per record.
- A successful ship (HTTP 2xx) **truncates** the file (clears log contents; metadata is recreated on the next write). Failed ships leave the file intact and the next ticker iteration retries.

The HTTP client timeout for ship requests is fixed (15 seconds in code).
