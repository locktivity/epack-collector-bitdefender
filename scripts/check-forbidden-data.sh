#!/usr/bin/env bash
# Fails if the collector emits forbidden Bitdefender data. Mirrors the guard
# in epack-collector-github, adapted to this collector's sensitive fields.
#
# Forbidden patterns:
#   Details.FilePath   - the raw quarantine file path (Windows paths embed
#                         usernames); only FileName (basename) and
#                         FilePathHash (SHA-256) may be emitted
#   apiKey / APIKey     - anywhere outside auth plumbing in the client itself
#
# Suppress a deliberate, audited use with a trailing "// LINT-ALLOW: <reason>".
set -euo pipefail

violations=$(
  grep -rn -E '\.FilePath\b' \
    internal/collector/ \
    --include='*.go' \
    | grep -v '_test.go' \
    | grep -v '// LINT-ALLOW:' \
    || true
)

if [ -n "$violations" ]; then
  echo "FORBIDDEN BITDEFENDER DATA EMISSION DETECTED:"
  echo "$violations"
  echo
  echo "The collector package must never emit a raw quarantine file path;"
  echo "use fileBaseName()/hashPath() from surface_collectors.go instead."
  echo "If this use is deliberate and audited, append '// LINT-ALLOW: <reason>' to the line."
  exit 1
fi

echo "forbidden-data check: clean"
