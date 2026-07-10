# epack-collector-bitdefender

Collects endpoint compliance posture from [Bitdefender GravityZone](https://www.bitdefender.com/business/support/en/77209-125277-public-api.html)
(Control Center's Public API) for inclusion in an [Evidence Pack](https://evidencepack.org).

It follows the same three-level collection convention as `epack-collector-github`:
`trust` (org-wide %), `audit` (per-computer inventory), `internal` (quarantine,
last scan, and enforced policies per computer). See [docs/levels.md](docs/levels.md)
for the full breakdown.

> **Scope note:** GravityZone's API doesn't distinguish "laptop" from
> "desktop" — both are `machineType: 1` ("computer"), as opposed to virtual
> machines, EC2 instances, or other device types. This collector treats all
> `machineType: 1` endpoints as in scope and documents this as a proxy for
> "laptop," not a guarantee. See docs/levels.md for detail.

## Configuration

```yaml
collectors:
  bitdefender:
    source: locktivity/epack-collector-bitdefender@^0.1
    config:
      base_url: https://cloud.gravityzone.bitdefender.com/api
      # EU tenants: https://cloudgz.gravityzone.bitdefender.com/api
      # On-premises: your Control Center's own API URL
      parent_group_id: ""   # optional; omit to scope to the whole company
      level: audit
    secrets:
      - BITDEFENDER_API_KEY
```

`BITDEFENDER_API_KEY` is a GravityZone API key generated under
**My Account > API keys** in Control Center. It's used as the HTTP Basic
auth username with an empty password, per GravityZone's API convention.

## Required GravityZone APIs on the key

Each API key is scoped to specific GravityZone APIs at creation time. Grant
only what the configured level needs:

| Surface | Gating API | Needed for |
|---------|-----------|------------|
| Compliance %, endpoint inventory | **Network** | trust / audit / internal |
| Per-endpoint policy + enabled modules | **Network** (`getManagedEndpointDetails`) | internal |
| Quarantine inventory | **Quarantine** | internal |

A missing API skips just that surface (recorded in `diagnostics`), so you
can grant incrementally — `trust` and `audit` only ever need the Network
API.

## What each level collects

- **trust**: `compliance.compliance_percentage` — the share of managed
  computers this collector considers compliant. No endpoint names.
- **audit**: adds `endpoints.per_endpoint[]` — name, OS, and the three
  booleans behind the compliance percentage (managed, policy applied,
  product not outdated).
- **internal**: adds `endpoints.per_endpoint[].last_scan_*` (last successful
  scan), `policies.per_endpoint[]` (assigned policy + enabled protection
  modules per computer), and `quarantine.per_computer[]` (quarantined items
  per computer, file path hashed rather than emitted in full).

See [docs/levels.md](docs/levels.md) for the exact compliance definition
(GravityZone has no single native "compliance %" in the Network API — this
collector derives one) and the full field-by-field breakdown.

## Never emitted, at any level

Quarantined-file full paths (only the base filename and a SHA-256 hash of
the full path are kept — full paths on Windows routinely embed a
username), the API key itself, and any endpoint data outside `machineType:
1` (computers) unless you extend the collector's scope deliberately.

## Status

Core collection logic, output schema, docs, tests, and CI/release automation
are in place, following the same structure as `epack-collector-github`
(mock-client test suite, `.github/workflows/ci.yaml` + `release.yaml`, SLSA
Level 3 provenance via `.slsa-goreleaser/`). Before treating this as
production-ready, validate the field shapes in `internal/bitdefender/`
against a live (or sandboxed) GravityZone tenant — they're transcribed from
Bitdefender's public API docs rather than captured from a live response.

## Development

```bash
# Build
go build -o epack-collector-bitdefender ./cmd/epack-collector-bitdefender

# Run locally (with epack SDK)
epack sdk run ./epack-collector-bitdefender

# Run conformance tests
epack sdk test ./epack-collector-bitdefender
```

## Testing

```bash
go test -race ./...
./scripts/check-forbidden-data.sh
```

## Release

Tag a version to trigger the release workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The GitHub Action will run tests and conformance checks, build multi-platform
binaries (linux/darwin, amd64/arm64), generate
[SLSA Level 3](https://slsa.dev/spec/v1.0/levels#build-l3) provenance
attestations, and publish to GitHub Releases — all release binaries carry
cryptographic provenance proving they were built from this repo's CI.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
