# Bitdefender GravityZone Endpoint Compliance Collector

Gathers endpoint compliance posture from Bitdefender GravityZone Control Center.

## What It Collects

- **Compliance**: an org-wide compliance percentage across managed computers (laptops/desktops)
- **Endpoints**: per-computer name, OS, and the signals behind the compliance percentage
- **Policies**: which GravityZone security policy is assigned to each computer and which
  protection modules (antimalware, firewall, device control, etc.) it has turned on
- **Quarantine**: quarantined threat activity per computer, with file paths hashed rather
  than emitted in full
- **Endpoint posture**: the share of computers with antimalware installed, antimalware
  healthy, and the EDR sensor installed, in the shared `evidencepack/endpoint-posture@v1`
  format (see [Endpoint posture](#endpoint-posture) below)

See [docs/levels.md](levels.md) for exactly what's included at each collection level, and
how this collector defines "compliant" (GravityZone's Network API has no single native
compliance-percentage field).

## Not Collected

GravityZone offers the following through its Public API, and the collector does not read them.

- **Missing patches.** GravityZone Patch Management lists the patches each endpoint is
  missing, with their CVEs. Patch Management is a GravityZone add-on. The collector writes no
  `vuln-scanning` file.
- **Control Center user accounts.** GravityZone's Accounts API lists the user accounts that
  sign in to Control Center and the role of each. It also says whether an account signs in
  through an identity provider and whether it has two-factor authentication on. The collector
  writes no `access-posture` file.
- **Incidents.** GravityZone's Incidents API lists the incidents GravityZone raised, with each
  one's status and priority. It needs a GravityZone license with access to incidents.

## Use Cases

- **Endpoint security evidence**: demonstrate AV/EDR coverage and policy enforcement for
  audits (SOC 2, ISO 27001, customer security questionnaires)
- **Continuous assurance**: track fleet compliance percentage over time
- **Incident review context**: see quarantine activity alongside policy/module state per
  machine

## How It Works

1. The collector authenticates to GravityZone Control Center's Public API using an API key
   over HTTP Basic auth (the JSON-RPC 2.0 convention GravityZone's API uses), and signs in
   with `getApiKeyDetails`. A rejected key fails the run with `auth_failed` (exit code 3).
2. It calls `getEndpointsList` (Network API, version 1.1) for every endpoint under the
   company or `parent_group_id`, subgroups included, with each agent's update state, to
   build the endpoint inventory and compute the compliance percentage
3. Bitdefender's API docs say to read the endpoints synced from Active Directory with
   `getNetworkInventoryItems`. The collector finds the Active Directory folder with it
   (Network API, version 1.1) and lists the endpoints below it. With `parent_group_id` set, it lists the
   endpoints below that group instead. An endpoint both lists hold counts once.
4. At every level, it calls `getManagedEndpointDetails` (Network API) once per computer
   with the agent, for its protection modules, license, and signature state
5. At `internal`, it also calls `getQuarantineItemsList` once for the whole company
   (Quarantine API), grouping results by computer client-side
6. The output is wrapped in the epack collector protocol envelope and written to stdout
   as `artifacts/bitdefender.details.json` and `artifacts/bitdefender.endpoint-posture.json`,
   with a collector result artifact (`artifacts/bitdefender.collector-result.json`) that
   records each value left out and why

## Endpoint posture

`artifacts/bitdefender.endpoint-posture.json` follows the `evidencepack/endpoint-posture@v1`
schema, with `provider: bitdefender`. `collect` lists it as `endpoint-posture`. GravityZone
is antivirus and EDR software, so the file holds only what GravityZone reports.

- `fleet.device_count` counts the computers (`machineType` 1). `scope.observed_device_count`
  counts every endpoint of every machine type, so the two can differ.
  `fleet.managed_device_count` counts the computers with the agent (`isManaged`).
- `protection.antimalware_installed_pct` is the share of computers with the antimalware
  module on.
- `protection.antimalware_healthy_pct` is the share with the antimalware module on, an
  active license, and current signatures. An out-of-date agent does not count against it.
  The detailed file's compliance percentage covers that.
- `protection.edr_installed_pct` is the share with the EDR sensor module on.
- A computer without the agent has no modules, so it counts as not installed and not
  healthy.

These values have an `unsupported` gap in the collector result, which does not make a run
partial:

| Value | Why it is left out |
|---|---|
| `fleet.mdm_enrolled_pct` and `mdm_enrolled_device_count` | GravityZone does not enroll computers in MDM |
| `hardening.firewall_enabled_pct` | GravityZone reports only its own firewall module, so a computer that uses the operating system's firewall would read as off |
| `hardening.screen_lock_compliant_pct` | GravityZone's API does not report a screen lock setting |
| `patching` | GravityZone does not report whether an operating system still gets security updates |
| `protection.edr_healthy_pct` | GravityZone does not report whether the EDR sensor is running and reporting |
| `compliance.compliant_pct` | GravityZone's API has no compliance verdict for a computer. The collector's compliance rule is in the detailed file |

`hardening.disk_encryption_pct` has a `not_read` gap, which does not make a run partial
either. GravityZone's Endpoint Encryption Status report gives each volume's encryption
status. The report comes from the Reports API, which this collector does not call.
`getManagedEndpointDetails` reports only whether the encryption module is on. The
`availability` reason for disk encryption is `not_read` as well.

A computer whose `getManagedEndpointDetails` call failed has no reading. The protection
percentages are then left out with the call's code. When an endpoint list or the Active
Directory folder could not be read in full, the fleet and protection values are left out.
`scope.discovery_complete` is then false for a list longer than the collector reads, and
null with the call's gap when a call failed.

At the audit level, the file adds the counts behind each percentage in `metric_coverage`
and one row per computer in `devices`, up to 20,000 rows. A row has the computer's name,
OS, management state, last sync with Control Center, protection readings, and modules.
GravityZone gives the last sync without a time zone, and the collector reads it as UTC.

See [Configuration](configuration.md) for setup instructions.
