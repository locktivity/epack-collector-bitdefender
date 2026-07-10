package collector

import "github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"

// filterComputers keeps only "computer" endpoints (machineType == 1):
// physical or virtual desktops/laptops, as opposed to EC2 instances or
// "other" device types. GravityZone's API has no dedicated laptop/desktop
// distinction; this is the closest available proxy for "laptop" the API
// offers, applied client-side since getEndpointsList has no machineType
// filter.
func filterComputers(endpoints []bitdefender.Endpoint) []bitdefender.Endpoint {
	out := make([]bitdefender.Endpoint, 0, len(endpoints))
	for _, e := range endpoints {
		if e.MachineType == bitdefender.MachineTypeComputer {
			out = append(out, e)
		}
	}
	return out
}

// isCompliant is this collector's compliance definition, computed entirely
// from fields already present on a getEndpointsList row (no extra API
// calls needed for the trust/audit-level view): the endpoint is actively
// managed, its assigned policy has been applied (not still pending), and
// its agent isn't flagged as out of date.
//
// This is a deliberately conservative definition and not a native
// GravityZone "compliance score" — GravityZone doesn't expose one via the
// Network API. If your org uses the separate Compliance Manager add-on
// with its own standards-based scoring, that would need its own API
// integration; this collector doesn't call it.
func isCompliant(e bitdefender.Endpoint) bool {
	return e.IsManaged && e.Policy.Applied && !e.ProductOutdated
}

// summarizeCompliance computes the trust-level org-wide rollup.
func summarizeCompliance(endpoints []bitdefender.Endpoint) ComplianceSummary {
	var compliant int
	for _, e := range endpoints {
		if isCompliant(e) {
			compliant++
		}
	}
	total := len(endpoints)
	summary := ComplianceSummary{
		CompliantCount:    compliant,
		NonCompliantCount: total - compliant,
	}
	if total > 0 {
		summary.CompliancePercentage = round2(100 * float64(compliant) / float64(total))
	}
	return summary
}

// round2 rounds to two decimal places, matching the precision used in the
// output schema.
func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
