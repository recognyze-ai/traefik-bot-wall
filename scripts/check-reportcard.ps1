# Mirrors Go Report Card checks: gofmt -s and gocyclo (complexity > 15).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

Write-Host "==> gofmt -s"
$unformatted = gofmt -s -l .
if ($unformatted) {
    Write-Error "files not gofmted with -s:`n$unformatted"
}

Write-Host "==> gocyclo (max complexity 15)"
$gocyclo = Get-Command gocyclo -ErrorAction SilentlyContinue
if (-not $gocyclo) {
    Write-Host "installing gocyclo..."
    go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
    $env:PATH = "$(go env GOPATH)\bin;$env:PATH"
}
$over = gocyclo -over 15 .
if ($LASTEXITCODE -ne 0 -or $over) {
    if ($over) { $over | Write-Host }
    throw "functions exceed cyclomatic complexity 15"
}

Write-Host "report card checks passed"
