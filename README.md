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
| Compliance %, endpoint inventory | **Network** (`getEndpointsList`, `getNetworkInventoryItems`) | trust / audit / internal |
| Endpoint posture | **Network** (`getManagedEndpointDetails`) | trust / audit / internal |
| Per-endpoint policy + enabled modules | **Network** (`getManagedEndpointDetails`) | internal |
| Quarantine inventory | **Quarantine** | internal |

A missing API leaves just that surface out, with a gap in the collector
result and an entry in `diagnostics`, so you can grant incrementally.
`trust` and `audit` only ever need the Network API.

## Failures and values left out

The collector signs in first with `getApiKeyDetails`. If GravityZone
rejects the API key, the run fails with the code `auth_failed` and exit
code 3. Invalid configuration (a missing or non-https `base_url`, a missing
key, or a `parent_group_id` GravityZone cannot find) fails with
`config_invalid` and exit code 2.

After signing in, the run succeeds with whatever it could read. A value it
could not read is null or absent, never a default such as 0 or false, and
`artifacts/bitdefender.collector-result.json` records why, with one of the
epack collector protocol's codes, along with the calls the collector made
and the APIs the key has enabled. The collector retries GravityZone's 429
and 5xx responses, and a JSON-RPC throttle (`-32003`) or server error
(`-32000`) in an HTTP 200 response, waiting as long as a `Retry-After`
header asks.

## What each level collects

- **trust**: `compliance.compliance_percentage`, the share of computers
  this collector considers compliant. No endpoint names. It is null when no
  computers are in scope.
- **audit**: adds `endpoints.per_endpoint[]`: name, OS, whether the
  computer is compliant, and the signals behind it (managed, policy
  applied, product outdated).
- **internal**: adds `endpoints.per_endpoint[].last_scan_*` (last successful
  scan), `policies.per_endpoint[]` (assigned policy + enabled protection
  modules per computer), and `quarantine.per_computer[]` (quarantined items
  per computer, file path hashed rather than emitted in full).

At every level the collector also writes
`artifacts/bitdefender.endpoint-posture.json` in the shared `evidencepack/endpoint-posture@v1` format: the share of computers with
antimalware installed, antimalware healthy, and the EDR sensor installed. At
audit it adds the counts and one row per computer. See
[docs/overview.md](docs/overview.md#endpoint-posture) for what it holds and
what GravityZone does not report.

See [docs/levels.md](docs/levels.md) for the exact compliance definition
(GravityZone has no single native "compliance %" in the Network API — this
collector derives one) and the full field-by-field breakdown.

## Never emitted, at any level

Quarantined-file full paths (only the base filename and a SHA-256 hash of
the full path are kept — full paths on Windows routinely embed a
username), the API key itself, and any endpoint data outside `machineType:
1` (computers) unless you extend the collector's scope deliberately.

## Status

Core collection logic, output schema (`docs/schema/v1.0.0.json`), docs,
tests, and CI/release automation are in place: mock-client tests, a
`componentsdk/collectortest` suite that replays GravityZone responses and
injects failures into every call, the shared epack collector CI workflow
called from `.github/workflows/ci.yaml`, and SLSA Level 3 provenance via
`.slsa-goreleaser/`. Before treating this as
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
