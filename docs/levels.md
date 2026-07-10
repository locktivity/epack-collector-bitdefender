# Collection Levels

Three cumulative levels, same convention as `epack-collector-github`:
`internal` is a strict superset of `audit`, which is a strict superset of
`trust`.

| Level | Question it answers | What's in the artifact |
|---|---|---|
| `trust` (default) | What fraction of laptops are compliant? | Org-wide compliance percentage only. No computer names. |
| `audit` | Which laptops, and why? | Per-computer name, OS, and the booleans behind the compliance percentage. |
| `internal` | What's actually happening on each laptop? | Last successful scan, quarantine activity, and enforced policy/modules, per computer. |

## Scope: what counts as a "laptop"

GravityZone's Network API reports a `machineType` per endpoint: `1` for a
physical or virtual computer, `2` for a VM under a hypervisor integration,
`3` for an EC2 instance, `0` for other device types. There is no separate
laptop/desktop flag. This collector treats `machineType: 1` as the scope for
"laptop," which will also include any desktop workstations GravityZone
manages the same way. If your GravityZone tenant tags device form factor
some other way (e.g. via custom groups or tags), filter on that separately
and adjust `filterComputers` in `internal/collector/compliance.go`.

## Compliance definition

GravityZone doesn't expose one native "compliance %" field for endpoints in
the Network API (the separate, license-gated Compliance Manager add-on has
its own standards-based scoring this collector doesn't call). Instead, this
collector derives compliance per computer from three fields already present
on every `getEndpointsList` row — no extra API calls:

```go
func isCompliant(e Endpoint) bool {
    return e.IsManaged && e.Policy.Applied && !e.ProductOutdated
}
```

- **`isManaged`**: the endpoint has an active GravityZone agent, not just
  a discovered/unmanaged device on the network.
- **`policy.applied`**: the assigned security policy has actually reached
  the endpoint (not still pending push).
- **`!productOutdated`**: the installed agent isn't flagged as out of date.

This is intentionally conservative and doesn't factor in things only
available per-endpoint (e.g. signature freshness, active infection) to keep
trust/audit cheap — one paginated list call regardless of fleet size. If you
want a stricter definition (e.g. also requiring a recent scan, or excluding
infected machines), extend `isCompliant`; the internal-level `Modules` and
malware-status data already collected per endpoint has what you'd need.

## What each level adds, per surface

### Compliance (`compliance`)

- **trust**: `compliance_percentage`, `compliant_count`, `non_compliant_count`.

### Endpoints (`endpoints`)

- **trust**: omitted.
- **audit**: `per_endpoint[]` rows — `name`, `operating_system`,
  `compliant`, `policy_applied`, `product_outdated`.
- **internal**: each row gains `last_scan_name` / `last_scan_date` (from
  GravityZone's `lastSuccessfulScan`).

### Policies (`policies`)

- **trust / audit**: omitted.
- **internal**: `per_endpoint[]` rows — `policy_id`, `policy_name`,
  `applied`, and `modules_enabled[]` (the protection modules GravityZone
  reports as turned on for that computer, e.g. `antimalware`, `firewall`,
  `deviceControl`). One `getManagedEndpointDetails` call per computer; a
  failed call for one computer degrades to a diagnostic warning and falls
  back to the policy assignment already known from the endpoint list,
  rather than dropping the row or failing the whole surface.

This surface only covers *which* policy is assigned and *which modules it
turns on* — not the full configuration inside each module (e.g. specific
firewall rules). Adding that would mean calling `getPolicyDetails` per
distinct policy and parsing its (large, module-specific) settings tree,
which is a reasonable follow-up but out of scope for this first pass.

### Quarantine (`quarantine`)

- **trust / audit**: omitted.
- **internal**: `total_count` plus `per_computer[]` rows — `threat_name`,
  `action_status` (GravityZone's raw status code; see their API reference
  for the current meaning, which this collector doesn't reinterpret),
  `date`, `file_name` (base name only), `file_path_hash` (SHA-256 of the
  full path).

One `getQuarantineItemsList` call for the whole company (paginated),
grouped by `endpointId` client-side — not one call per computer.

## Never emitted, at any level

The full quarantined-file path (Windows paths routinely embed a username
under `C:\Users\<name>\...`; only the base filename and a path hash are
kept), the GravityZone API key, and detailed per-module policy settings
(only which modules are on/off, not their configuration).

## Truncation

| Surface | Cap | Sort (most-significant kept) |
|---|---|---|
| Endpoints | 20,000 | non-compliant first, then name ascending |
| Quarantine | 20,000 rows (all computers combined) | computer name, then most recent first |

`policies.per_endpoint[]` is not capped independently — it's one row per
computer already bounded by the Endpoints cap upstream.
