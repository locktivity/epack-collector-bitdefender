# Bitdefender GravityZone Endpoint Compliance Collector

Gathers endpoint compliance posture from Bitdefender GravityZone Control Center.

## What It Collects

- **Compliance**: an org-wide compliance percentage across managed computers (laptops/desktops)
- **Endpoints**: per-computer name, OS, and the signals behind the compliance percentage
- **Policies**: which GravityZone security policy is assigned to each computer and which
  protection modules (antimalware, firewall, device control, etc.) it has turned on
- **Quarantine**: quarantined threat activity per computer, with file paths hashed rather
  than emitted in full

See [docs/levels.md](levels.md) for exactly what's included at each collection level, and
how this collector defines "compliant" (GravityZone's Network API has no single native
compliance-percentage field).

## Use Cases

- **Endpoint security evidence**: demonstrate AV/EDR coverage and policy enforcement for
  audits (SOC 2, ISO 27001, customer security questionnaires)
- **Continuous assurance**: track fleet compliance percentage over time
- **Incident review context**: see quarantine activity alongside policy/module state per
  machine

## How It Works

1. The collector authenticates to GravityZone Control Center's Public API using an API key
   over HTTP Basic auth (the JSON-RPC 2.0 convention GravityZone's API uses)
2. It calls `getEndpointsList` (Network API) to build the endpoint inventory and compute
   the compliance percentage — one paginated call, regardless of level
3. At `internal`, it additionally calls `getManagedEndpointDetails` per computer (Network
   API) for enabled protection modules, and `getQuarantineItemsList` once for the whole
   company (Quarantine API), grouping results by computer client-side
4. The output is wrapped in the epack collector protocol envelope and written to stdout

See [Configuration](configuration.md) for setup instructions.
