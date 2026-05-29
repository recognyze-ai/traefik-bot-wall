#!/usr/bin/env bash
# Mirrors Go Report Card checks: gofmt -s and gocyclo (complexity > 15).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

echo "==> gofmt -s"
unformatted="$(gofmt -s -l .)"
if [ -n "$unformatted" ]; then
  echo "files not gofmted with -s:" >&2
  echo "$unformatted" >&2
  exit 1
fi

echo "==> gocyclo (max complexity 15)"
if ! command -v gocyclo >/dev/null 2>&1; then
  echo "installing gocyclo..."
  go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
  export PATH="${PATH}:$(go env GOPATH)/bin"
fi
if ! gocyclo -over 15 .; then
  echo "functions exceed cyclomatic complexity 15" >&2
  exit 1
fi

echo "report card checks passed"
