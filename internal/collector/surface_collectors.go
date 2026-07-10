package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"sort"
	"strings"

	"github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"
	"github.com/locktivity/epack/componentsdk"
)

// Per-surface truncation caps bounding output size and pagination.
const (
	EndpointsCap  = 20000
	QuarantineCap = 20000
)

// collectionPass carries the shared state for one audit/internal surface
// pass, mirroring epack-collector-github's collectionPass.
type collectionPass struct {
	ctx     context.Context
	posture *EndpointPosture
	diag    *diagnostics
	level   componentsdk.Level
	laptops []bitdefender.Endpoint
}

func (p *collectionPass) internal() bool {
	return p.level.AtLeast(componentsdk.LevelInternal)
}

// collectEndpoints builds the per-computer inventory. Audit emits name and
// the booleans behind the trust-level compliance percentage; internal adds
// the last successful scan.
func (c *Collector) collectEndpoints(p *collectionPass) {
	rows := make([]EndpointRow, 0, len(p.laptops))
	for _, e := range p.laptops {
		row := EndpointRow{
			Name:            e.Name,
			OperatingSystem: e.OperatingSystemVersion,
			Compliant:       isCompliant(e),
			PolicyApplied:   e.Policy.Applied,
			ProductOutdated: e.ProductOutdated,
		}
		if p.internal() && e.LastSuccessfulScan != nil {
			row.LastScanName = e.LastSuccessfulScan.Name
			row.LastScanDate = e.LastSuccessfulScan.Date
		}
		rows = append(rows, row)
	}

	kept, dropped, truncated := Truncate(rows, EndpointsCap, func(a, b EndpointRow) bool {
		// Non-compliant first (the rows worth reviewing), then name.
		if a.Compliant != b.Compliant {
			return !a.Compliant
		}
		return a.Name < b.Name
	})
	p.posture.Endpoints = &Endpoints{
		PerEndpoint:      kept,
		Truncated:        truncated,
		TruncatedDropped: dropped,
	}
}

// collectPolicies gathers each computer's assigned policy and enabled
// protection modules, via one getManagedEndpointDetails call per computer.
// Internal-only. A single failed detail call degrades to a warning for that
// computer rather than failing the whole surface.
func (c *Collector) collectPolicies(p *collectionPass) {
	if !p.internal() {
		return
	}

	rows := make([]EndpointPolicyRow, 0, len(p.laptops))
	permissionDenied := false

	for _, e := range p.laptops {
		detail, err := c.client.GetManagedEndpointDetails(p.ctx, e.ID)
		if err != nil {
			if isDenied(err) {
				permissionDenied = true
			} else {
				p.diag.surfaceWarning("policies", "could not fetch detail for "+e.Name)
			}
			// Fall back to what the endpoint list already told us about the
			// policy assignment, so the row isn't dropped entirely.
			rows = append(rows, EndpointPolicyRow{
				Computer:   e.Name,
				PolicyID:   e.Policy.ID,
				PolicyName: e.Policy.Name,
				Applied:    e.Policy.Applied,
			})
			continue
		}
		rows = append(rows, EndpointPolicyRow{
			Computer:       e.Name,
			PolicyID:       detail.Policy.ID,
			PolicyName:     detail.Policy.Name,
			Applied:        detail.Policy.Applied,
			ModulesEnabled: enabledModuleNames(detail.Modules),
		})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].Computer < rows[j].Computer })
	p.posture.Policies = &Policies{PerEndpoint: rows}

	if permissionDenied {
		p.diag.surfacePermissionDenied("policies", "Network")
	}
}

// enabledModuleNames returns the sorted names of modules reported enabled.
func enabledModuleNames(modules map[string]bool) []string {
	if len(modules) == 0 {
		return nil
	}
	names := make([]string, 0, len(modules))
	for name, enabled := range modules {
		if enabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// collectQuarantine gathers the company-wide quarantine list once and
// groups it by computer client-side, instead of one filtered call per
// endpoint. Internal-only.
func (c *Collector) collectQuarantine(p *collectionPass) {
	if !p.internal() {
		return
	}

	items, err := c.client.ListQuarantineItems(p.ctx)
	if err != nil {
		if isDenied(err) {
			p.diag.surfacePermissionDenied("quarantine", "Quarantine")
		} else {
			p.diag.surfaceWarning("quarantine", "could not list quarantine items")
		}
		return
	}

	nameByID := make(map[string]string, len(p.laptops))
	for _, e := range p.laptops {
		nameByID[e.ID] = e.Name
	}

	q := &Quarantine{TotalCount: len(items)}
	rows := make([]QuarantineRow, 0, len(items))
	for _, item := range items {
		computer := nameByID[item.EndpointID]
		if computer == "" {
			// Item belongs to an endpoint outside this run's scope (e.g. not
			// a "computer" machine type); skip rather than emit an
			// unidentified row.
			continue
		}
		row := QuarantineRow{
			Computer:     computer,
			ThreatName:   item.ThreatName,
			ActionStatus: item.ActionStatus,
			Date:         item.Date,
		}
		if item.Details != nil && item.Details.FilePath != "" { // LINT-ALLOW: read only to hash/truncate below, never stored or emitted raw
			row.FileName = fileBaseName(item.Details.FilePath) // LINT-ALLOW: basename only, no directory component
			row.FilePathHash = hashPath(item.Details.FilePath) // LINT-ALLOW: hashed, not the raw path
		}
		rows = append(rows, row)
	}

	kept, dropped, truncated := Truncate(rows, QuarantineCap, func(a, b QuarantineRow) bool {
		if a.Computer != b.Computer {
			return a.Computer < b.Computer
		}
		return a.Date > b.Date
	})
	q.PerComputer = kept
	q.Truncated = truncated
	q.TruncatedDropped = dropped
	p.posture.Quarantine = q
}

// fileBaseName extracts just the file name from a possibly-Windows path,
// discarding directory components (which routinely embed a username).
func fileBaseName(p string) string {
	norm := strings.ReplaceAll(p, "\\", "/")
	return path.Base(norm)
}

// hashPath returns a SHA-256 hex digest of the full path, so two quarantine
// entries on the same path can be correlated without emitting the path
// itself.
func hashPath(p string) string {
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// isDenied reports whether err is (or wraps) a permission denial.
func isDenied(err error) bool {
	return err != nil && errors.Is(err, bitdefender.ErrPermissionDenied)
}
