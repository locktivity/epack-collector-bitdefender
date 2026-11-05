// Package collector collects Bitdefender GravityZone endpoint compliance
// posture at three cumulative levels (trust / audit / internal), following
// the same collection-level convention as epack-collector-github.
//
// A value the collector could not read is null or absent, and the run's
// collector result records why. docs/schema/v1.0.0.json describes the
// artifact.
package collector

// EndpointPosture is the root of the collected artifact.
type EndpointPosture struct {
	CollectedAtLevel string `json:"collected_at_level"`
	Scope            Scope  `json:"scope"`

	// Compliance is trust-level: an org-wide percentage only, no endpoint
	// names or identifiers.
	Compliance ComplianceSummary `json:"compliance"`

	// Endpoints is audit-level and above (nil at trust).
	Endpoints *Endpoints `json:"endpoints,omitempty"`

	// Quarantine and Policies are internal-only (nil below internal).
	Quarantine *Quarantine `json:"quarantine,omitempty"`
	Policies   *Policies   `json:"policies,omitempty"`

	Diagnostics Diagnostics `json:"diagnostics"`

	// normalized is the endpoint-posture artifact built in the same pass. It
	// is not serialized.
	normalized *Normalized
}

// Normalized returns the evidencepack/endpoint-posture@v1 artifact built
// with the posture, or nil when the run does not collect it.
func (p *EndpointPosture) Normalized() *Normalized {
	return p.normalized
}

// Scope describes what was in scope for this run.
type Scope struct {
	// TotalManagedComputers is the count of GravityZone endpoints with
	// machineType "computer" (physical or virtual desktop/laptop), with or
	// without the GravityZone agent, from getEndpointsList and the Active
	// Directory folder together. GravityZone's API does not distinguish
	// laptop vs. desktop form factor; this collector treats "computer"
	// endpoints (as opposed to EC2 instances or "other" device types) as the
	// closest available proxy for "laptop". See docs/levels.md.
	TotalManagedComputers *int `json:"total_managed_computers"`
}

// ComplianceSummary is the trust-level org-wide signal.
//
// GravityZone does not expose a single native "compliance %" for endpoints
// in the Network API. This collector derives one from three signals present
// on every getEndpointsList row (no extra API calls): the endpoint is
// managed, its assigned policy is applied (not still pending push), and its
// agent is not flagged out of date. See docs/levels.md for the exact
// definition and how it can be adjusted.
type ComplianceSummary struct {
	CompliancePercentage *float64 `json:"compliance_percentage"`
	CompliantCount       *int     `json:"compliant_count"`
	NonCompliantCount    *int     `json:"non_compliant_count"`
}

// Endpoints is the per-computer inventory (audit+).
type Endpoints struct {
	PerEndpoint      []EndpointRow `json:"per_endpoint"`
	Truncated        bool          `json:"truncated,omitempty"`
	TruncatedDropped int           `json:"truncated_dropped,omitempty"`
}

// EndpointRow is one computer.
//
// Audit has the name and the signals behind the trust-level compliance
// percentage (so a reviewer can see *why* a machine is flagged
// non-compliant, not just the aggregate). Internal adds the last successful
// scan. Per-endpoint policy assignment and enabled modules live on the
// separate Policies surface (internal-only), and quarantine activity lives
// on the separate Quarantine surface (internal-only).
type EndpointRow struct {
	Name            string `json:"name"`
	OperatingSystem string `json:"operating_system,omitempty"`
	Managed         *bool  `json:"managed,omitempty"`
	Compliant       *bool  `json:"compliant"`
	PolicyApplied   *bool  `json:"policy_applied,omitempty"`
	ProductOutdated *bool  `json:"product_outdated,omitempty"`

	// Internal-only.
	LastScanName string `json:"last_scan_name,omitempty"`
	LastScanDate string `json:"last_scan_date,omitempty"`
}

// Quarantine is the per-computer quarantine inventory (internal-only).
type Quarantine struct {
	TotalCount       int             `json:"total_count"`
	PerComputer      []QuarantineRow `json:"per_computer"`
	Truncated        bool            `json:"truncated,omitempty"`
	TruncatedDropped int             `json:"truncated_dropped,omitempty"`
}

// QuarantineRow is one quarantined item on one computer.
//
// FileName is the file's base name only; FilePathHash is a SHA-256 of the
// full path. The full path is never emitted, since on Windows it routinely
// embeds a username (C:\Users\<name>\Downloads\...). ActionStatus is the
// raw GravityZone status code; see Bitdefender's API reference for the
// current code-to-meaning mapping, which this collector does not
// reinterpret to avoid getting out of sync with GravityZone's own docs.
type QuarantineRow struct {
	Computer     string `json:"computer"`
	ThreatName   string `json:"threat_name"`
	ActionStatus *int   `json:"action_status,omitempty"`
	Date         string `json:"date,omitempty"`
	FileName     string `json:"file_name,omitempty"`
	FilePathHash string `json:"file_path_hash,omitempty"`
}

// Policies is the assigned-policy / enforced-module inventory
// (internal-only). This is the "what security controls are enforced on
// this laptop" surface: which policy is assigned and whether it has taken
// effect, plus which protection modules that policy has turned on for the
// endpoint.
type Policies struct {
	PerEndpoint []EndpointPolicyRow `json:"per_endpoint"`
}

// EndpointPolicyRow is one computer's policy assignment and enabled
// modules. ModulesEnabled lists only modules currently reported as
// enabled (e.g. "antimalware", "firewall", "deviceControl"); the module
// names are whatever GravityZone's getManagedEndpointDetails API returns.
// A computer without the GravityZone agent has none.
type EndpointPolicyRow struct {
	Computer       string   `json:"computer"`
	PolicyID       string   `json:"policy_id,omitempty"`
	PolicyName     string   `json:"policy_name,omitempty"`
	Applied        *bool    `json:"applied,omitempty"`
	ModulesEnabled []string `json:"modules_enabled"`
}

// Diagnostics records permission problems and other non-fatal warnings
// encountered during collection.
type Diagnostics struct {
	PermissionErrors []string `json:"permission_errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}
