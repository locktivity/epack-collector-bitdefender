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
compliant := isManaged && policy.applied && !productOutdated
```

- **`isManaged`**: the endpoint has an active GravityZone agent, not just
  a discovered/unmanaged device on the network. A computer without the
  agent is non-compliant whatever else its row says.
- **`policy.applied`**: the assigned security policy has actually reached
  the endpoint (not still pending push).
- **`!productOutdated`**: the installed agent isn't flagged as out of date.
  GravityZone reports `productOutdated` only when asked to, so the
  collector requests it with the `returnProductOutdated` option.

When GravityZone leaves out a field a managed computer's answer needs, that
computer's `compliant` is null, and the org-wide percentage and counts are
left out, with a `partial` gap in the collector result counting the
computers that could not be judged.

This is intentionally conservative and doesn't factor in things only
available per-endpoint (e.g. signature freshness, active infection). The
endpoint-posture file's `protection.antimalware_healthy_pct` covers signature
freshness and the license, from the `getManagedEndpointDetails` call the
collector makes per computer at every level. If you want a stricter compliance definition (e.g.
also requiring a recent scan, or excluding infected machines), extend
`signals.compliant` in `internal/collector/compliance.go`; the `Modules` and
malware-status data already collected per endpoint has what you'd need.

## What each level adds, per surface

### Compliance (`compliance`)

- **trust**: `compliance_percentage`, `compliant_count`, `non_compliant_count`.
  The percentage is null when no computers are in scope.

The endpoint list covers every endpoint under the company, or under
`parent_group_id`, including its subgroups. It comes from version 1.1 of
`getEndpointsList`, read page by page until GravityZone reports no more
records. A page without `hasMoreRecords` fails the read with
`invalid_response`, as a page without its items list does, and the values
built from the list are left out.

Bitdefender's API docs say to read the endpoints in the Active Directory
folder with `getNetworkInventoryItems`. The collector reads them with version
1.1 of that method. It finds the folder by its name, Active Directory,
and lists every endpoint below it, page by page. With `parent_group_id` set,
it lists the endpoints below that group instead. Each endpoint ID counts once,
and an endpoint both lists hold keeps its `getEndpointsList` row. When the
folder cannot be read, the computer count and the compliance values are left
out, and the rows from `getEndpointsList` stay with a `partial` gap.

### Endpoints (`endpoints`)

- **trust**: omitted.
- **audit**: `per_endpoint[]` rows: `name`, `operating_system`, `managed`,
  `compliant`, `policy_applied`, `product_outdated`. `policy_applied` and
  `product_outdated` are absent when GravityZone does not report them, as
  for a computer without the agent.
- **internal**: each row gains `last_scan_name` / `last_scan_date` (from
  GravityZone's `lastSuccessfulScan`, which the collector requests with the
  `includeScanLogs` option). They are absent for a computer with no
  successful scan.

### Policies (`policies`)

- **trust / audit**: omitted.
- **internal**: `per_endpoint[]` rows — `policy_id`, `policy_name`,
  `applied`, and `modules_enabled[]` (the protection modules GravityZone
  reports as turned on for that computer, e.g. `antimalware`, `firewall`,
  `deviceControl`). The policy assignment comes from the endpoint list.
  The modules come from one `getManagedEndpointDetails` call per computer
  with the agent; a computer without it has an empty `modules_enabled` and
  gets no call. `artifacts/bitdefender.endpoint-posture.json` uses the same
  answers at every level, so the collector makes each call once. A failed call leaves that computer's `modules_enabled` null,
  with a gap in the collector result and a diagnostic warning; the row
  stays.

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
  `date` (GravityZone's `quarantinedOn`), `file_name` (base name only),
  `file_path_hash` (SHA-256 of the full path).

One `getQuarantineItemsList` call for the whole company (paginated),
grouped by `endpointId` client-side, not one call per computer. Pages are
read up to the `pagesCount` GravityZone reports.

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

`policies.per_endpoint[]` has one row per computer and is not capped. The
`devices` rows in `artifacts/bitdefender.endpoint-posture.json` stop at
20,000, ordered by computer name, with a `too_large` gap past the cap.

The collector reads at most 50,000 endpoints and 50,000 quarantined items.
Past either limit, the values built from that list are left out with a
`too_large` gap rather than counted in part.

## Values left out

After the sign-in, a call that fails leaves out the values built from it,
as null or absent, and `artifacts/bitdefender.collector-result.json`
records each one with a code saying why. A failed endpoint list leaves out
everything except `quarantine.total_count`, which comes from its own call.
A value is never replaced by a default such as 0, false, or an empty list.
