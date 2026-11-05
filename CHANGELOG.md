# Changelog

## Unreleased

## v0.2.0

- The collector is built on epack v0.10.0. The detailed artifact moves from `artifacts/bitdefender.json` to `artifacts/bitdefender.details.json`, the path epack's `ArtifactPath` gives it. A reader of the old path needs the new one
- A new file, `artifacts/bitdefender.endpoint-posture.json`, holds endpoint posture as `evidencepack/endpoint-posture@v1`, with `provider: bitdefender`. `collect` lists it as `endpoint-posture`, and the build file and `--capabilities` list its schema ID.
- The endpoint-posture file holds the share of computers with antimalware installed, antimalware healthy, and the EDR sensor installed. Antimalware counts as healthy when its module is on, the license is active, and the signatures are current. A computer without the GravityZone agent counts as not installed. At audit, the file adds the counts behind each share and one row per computer.
- Values GravityZone's API does not report are left out of the endpoint-posture file. These include the host firewall, screen lock, patching, MDM enrollment, EDR health, and a compliance verdict. Each has an `unsupported` gap, which does not make the run partial. `docs/overview.md` lists them.
- Disk encryption is left out of the endpoint-posture file with a `not_read` gap, which does not make the run partial either. GravityZone reports it in the Endpoint Encryption Status report of its Reports API, which the collector does not call. Disk encryption's `availability` reason is also `not_read`.
- `scope.discovery_complete` is false when an endpoint list holds more endpoints than the collector reads. When a failed call leaves it unknown, it is null with that call's gap.
- The collector now calls `getManagedEndpointDetails` once per computer with the agent at every level. It used to call it at `internal` only. With `collect: [details]` at `trust` or `audit`, the run skips these calls. They need the Network API, which the key already has.
- The collector now reads the computers in the Active Directory folder with `getNetworkInventoryItems`, as Bitdefender's API docs say to. `scope.total_managed_computers`, the compliance values, and the endpoint, policy, and quarantine rows include them. Each endpoint counts once. For a company with computers synced from Active Directory, these counts can go up. The call needs the Network API.
- When the Active Directory folder cannot be read, `scope.total_managed_computers` and the compliance values are left out with a gap. The rows from `getEndpointsList` stay, with a `partial` gap.
- Each operation in the collector result lists the GravityZone API it needs as `permission`, such as `network`. A gap from a denied call has that API as its `missing_permission`.
