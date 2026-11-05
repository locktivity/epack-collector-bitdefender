package collector

import (
	"fmt"

	"github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"
	"github.com/locktivity/epack/componentsdk"
)

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

// signals are the three getEndpointsList fields compliance is derived from.
// Each is nil when GravityZone left it out.
type signals struct {
	managed         *bool
	policyApplied   *bool
	productOutdated *bool
}

func signalsOf(e bitdefender.Endpoint) signals {
	s := signals{managed: e.IsManaged, productOutdated: e.ProductOutdated}
	if e.Policy != nil {
		s.policyApplied = e.Policy.Applied
	}
	return s
}

// compliant is this collector's compliance definition, computed entirely
// from fields already present on a getEndpointsList row (no extra API
// calls needed for the trust/audit-level view): the endpoint is actively
// managed, its assigned policy has been applied (not still pending), and
// its agent isn't flagged as out of date. A computer without the agent is
// not compliant whatever else its row says. It returns nil when GravityZone
// left out a field the answer needs.
//
// This is a deliberately conservative definition and not a native
// GravityZone "compliance score": GravityZone doesn't expose one via the
// Network API. If your org uses the separate Compliance Manager add-on
// with its own standards-based scoring, that would need its own API
// integration; this collector doesn't call it.
func (s signals) compliant() *bool {
	if s.managed == nil {
		return nil
	}
	if !*s.managed {
		return boolPtr(false)
	}
	if s.policyApplied == nil || s.productOutdated == nil {
		return nil
	}
	return boolPtr(*s.policyApplied && !*s.productOutdated)
}

// signalField names a signal in an endpoint row and in GravityZone's
// response.
type signalField struct {
	row, source string
}

// missing lists the signals compliance needs that GravityZone left out.
func (s signals) missing() []signalField {
	if s.managed == nil {
		return []signalField{{"managed", "isManaged"}}
	}
	if !*s.managed {
		return nil
	}
	var out []signalField
	if s.policyApplied == nil {
		out = append(out, signalField{"policy_applied", "policy.applied"})
	}
	if s.productOutdated == nil {
		out = append(out, signalField{"product_outdated", "productOutdated"})
	}
	return out
}

// summarizeCompliance computes the trust-level org-wide rollup. A computer
// whose compliance is unknown leaves the rollups out as partial.
func (c *Collector) summarizeCompliance(p *collectionPass) {
	rollups := []string{"/compliance/compliance_percentage", "/compliance/compliant_count", "/compliance/non_compliant_count"}
	if p.listErr != nil {
		c.rec.NotCollected(at("/scope/total_managed_computers"), p.listErr)
		for _, pointer := range rollups {
			c.rec.NotCollected(at(pointer), p.listErr)
		}
		return
	}
	if p.adErr != nil {
		// The computers in the Active Directory folder are missing from the
		// counts.
		c.rec.NotCollected(at("/scope/total_managed_computers"), p.adErr)
		for _, pointer := range rollups {
			c.rec.NotCollected(at(pointer), p.adErr)
		}
		return
	}
	total := len(p.computers)
	p.posture.Scope.TotalManagedComputers = &total

	var compliant, unknown int
	for _, e := range p.computers {
		switch v := signalsOf(e).compliant(); {
		case v == nil:
			unknown++
		case *v:
			compliant++
		}
	}
	if unknown > 0 {
		err := componentsdk.CodeError(componentsdk.CodeInvalidResponse,
			fmt.Errorf("getEndpointsList left out a field compliance needs for %d of %d computers", unknown, total))
		for _, pointer := range rollups {
			c.rec.Partial(at(pointer), unknown, err)
		}
		return
	}
	nonCompliant := total - compliant
	p.posture.Compliance.CompliantCount = &compliant
	p.posture.Compliance.NonCompliantCount = &nonCompliant
	if total > 0 {
		pct := round2(100 * float64(compliant) / float64(total))
		p.posture.Compliance.CompliancePercentage = &pct
	}
}

// round2 rounds to two decimal places, matching the precision used in the
// output schema.
func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

func boolPtr(b bool) *bool { return &b }
