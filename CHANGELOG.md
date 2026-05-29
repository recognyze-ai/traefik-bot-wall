# Changelog

All notable changes to the [Recognyze Bot Wall Traefik Plugin](https://github.com/recognyze-ai/traefik-bot-wall) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0]

### Added

- Proactive publisher API key rotation before `expiration_date` (default 14-day buffer, WordPress plugin parity).
- `PublisherKeyManager` with encrypted state file (`publisherAPIKeyStateFile`), metadata sync, and background rotation loop.
- Config: `publisherAPIKeyRotationEnabled` (default on when `publisherLogsURL` is set), `publisherAPIKeyRotationBufferDays`, `publisherAPIKeyMetadataSyncInterval`, `publisherAPIKeyEncryptAtRest`, `publisherAPIKeyEncryptionKeyFile`, `publisherAPIBaseURL`.

### Changed

- Publisher log shipping uses the live secret from the state file (bootstrap `publisherAPIKey` in YAML is not updated by the plugin).

## [0.3.0] - 2026-05-21
### Initial changelog tracking

- Begin tracking plugin development and notable changes in this file for transparency and historical reference.
- For pre-release and early work, see commit history for additional context.

### Added

- README banner image for Traefik / Recognyze.ai branding (`assets/r7e_banner_traefik.png`).

## [0.2.0] - 2026-05-21

### Added
- MIT `LICENSE` file (Copyright 2025–2026 Recognyze.ai).
- Recognyze logo for the Traefik Plugin Catalog (`.traefik.yml` `iconPath`, `assets/recognyze-logo.png`).
- [Go Report Card](https://goreportcard.com/report/github.com/recognyze-ai/traefik-bot-wall) badge in `README.md`.
- Tests for IP verification normalization (`botdef_parse_test.go`) and UA identity matching (`softmax_test.go`).

### Changed
- Refactored `config.go`, `softmax.go`, `logging.go`, and `botdef_parse.go` to lower cyclomatic complexity (Go Report Card `gocyclo`).
- Updated sample dynamic config in `traefik/dynamic/botwall.yml`.

