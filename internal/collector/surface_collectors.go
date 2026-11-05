package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"
	"github.com/locktivity/epack/componentsdk"
)

// Per-surface truncation caps bounding output size.
const (
	EndpointsCap  = 20000
	QuarantineCap = 20000
)

// collectionPass carries the shared state for one collection pass,
// mirroring epack-collector-github's collectionPass.
type collectionPass struct {
	ctx     context.Context
	posture *EndpointPosture
	diag    *diagnostics
	level   componentsdk.Level
	// all is every endpoint getEndpointsList and the Active Directory folder
	// list, of every machine type, each endpoint ID once.
	all       []bitdefender.Endpoint
	computers []bitdefender.Endpoint
	// listErr is why the endpoint list could not be read, if it could not.
	listErr error
	// adErr is why the endpoints in the Active Directory folder could not be
	// read, if they could not. The computers then hold only those
	// getEndpointsList lists.
	adErr error
	// details holds each managed computer's getManagedEndpointDetails
	// answer, by endpoint ID, when the run needs them.
	details map[string]detailRead
}

func (p *collectionPass) internal() bool {
	return p.level.AtLeast(componentsdk.LevelInternal)
}

// fleetErr is why the computers read are not every computer in scope, or
// nil when they are.
func (p *collectionPass) fleetErr() error {
	if p.listErr != nil {
		return p.listErr
	}
	return p.adErr
}

// detailRead is one getManagedEndpointDetails answer, or the error the call
// failed with.
type detailRead struct {
	detail *bitdefender.EndpointDetail
	err    error
}

// listActiveDirectory reads the endpoints in the Active Directory folder,
// which Bitdefender's docs say to read with getNetworkInventoryItems. Without
// parent_group_id it finds the
// folder by name and lists the endpoints below it. With parent_group_id it
// lists the endpoints below that group, which can be a group in the Active
// Directory folder.
func (c *Collector) listActiveDirectory(ctx context.Context, scanLogs bool) ([]bitdefender.Endpoint, error) {
	parents := []string{c.config.ParentGroupID}
	if c.config.ParentGroupID == "" {
		folders, err := c.client.FindActiveDirectoryFolders(ctx)
		if err != nil {
			return nil, err
		}
		parents = folders
	}
	var all []bitdefender.Endpoint
	for _, parent := range parents {
		endpoints, err := c.client.ListInventoryEndpoints(ctx, parent, scanLogs)
		if err != nil {
			return nil, err
		}
		all = append(all, endpoints...)
	}
	return all, nil
}

// mergeEndpoints joins getEndpointsList's endpoints with the Active
// Directory folder's, keeping each endpoint ID once. An endpoint both lists
// hold keeps its getEndpointsList row.
func mergeEndpoints(listed, inventory []bitdefender.Endpoint) []bitdefender.Endpoint {
	seen := make(map[string]bool, len(listed)+len(inventory))
	out := make([]bitdefender.Endpoint, 0, len(listed)+len(inventory))
	for _, list := range [][]bitdefender.Endpoint{listed, inventory} {
		for _, e := range list {
			if e.ID != "" && seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			out = append(out, e)
		}
	}
	return out
}

// readDetails calls getManagedEndpointDetails once for each computer that
// is not known to lack the agent. GravityZone has no details for a computer
// without it.
func (c *Collector) readDetails(p *collectionPass) {
	p.details = map[string]detailRead{}
	var todo []bitdefender.Endpoint
	for _, e := range p.computers {
		if e.IsManaged != nil && !*e.IsManaged {
			continue
		}
		todo = append(todo, e)
	}
	for i, e := range todo {
		if _, ok := p.details[e.ID]; ok {
			continue
		}
		c.progress(int64(i+1), int64(len(todo)), "Fetching endpoint details")
		detail, err := c.client.GetManagedEndpointDetails(p.ctx, e.ID)
		p.details[e.ID] = detailRead{detail: detail, err: err}
	}
}

// collectEndpoints builds the per-computer inventory. Audit emits name and
// the signals behind the trust-level compliance percentage; internal adds
// the last successful scan.
func (c *Collector) collectEndpoints(p *collectionPass) {
	if p.listErr != nil {
		c.rec.NotCollected(at("/endpoints"), p.listErr)
		return
	}
	rows := make([]EndpointRow, 0, len(p.computers))
	for _, e := range p.computers {
		s := signalsOf(e)
		row := EndpointRow{
			Name:            e.Name,
			OperatingSystem: e.OperatingSystemVersion,
			Managed:         s.managed,
			Compliant:       s.compliant(),
			PolicyApplied:   s.policyApplied,
			ProductOutdated: s.productOutdated,
		}
		if p.internal() && e.LastSuccessfulScan != nil {
			row.LastScanName = e.LastSuccessfulScan.Name
			row.LastScanDate = e.LastSuccessfulScan.Date
		}
		rows = append(rows, row)
	}

	kept, dropped, truncated := Truncate(rows, EndpointsCap, func(a, b EndpointRow) bool {
		// Non-compliant first (the rows worth reviewing), then unknown, then
		// name.
		if ra, rb := reviewRank(a.Compliant), reviewRank(b.Compliant); ra != rb {
			return ra < rb
		}
		return a.Name < b.Name
	})
	p.posture.Endpoints = &Endpoints{
		PerEndpoint:      kept,
		Truncated:        truncated,
		TruncatedDropped: dropped,
	}
	if p.adErr != nil {
		c.rec.Partial(at("/endpoints/per_endpoint"), 0, p.adErr)
	}
	for i, row := range kept {
		if row.Compliant != nil {
			continue
		}
		var cause error
		for _, f := range (signals{managed: row.Managed, policyApplied: row.PolicyApplied, productOutdated: row.ProductOutdated}).missing() {
			err := componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("getEndpointsList reported no %s for the computer", f.source))
			if cause == nil {
				cause = err
			}
			c.rec.NotCollected(at(fmt.Sprintf("/endpoints/per_endpoint/%d/%s", i, f.row)), err)
		}
		c.rec.NotCollected(at(fmt.Sprintf("/endpoints/per_endpoint/%d/compliant", i)), cause)
	}
}

func reviewRank(compliant *bool) int {
	switch {
	case compliant == nil:
		return 1
	case *compliant:
		return 2
	default:
		return 0
	}
}

// collectPolicies gathers each computer's assigned policy, from the
// endpoint list, and its enabled protection modules, from the
// getManagedEndpointDetails answer readDetails got for each managed
// computer. Internal-only. A failed detail call leaves that computer's
// modules out with a gap.
func (c *Collector) collectPolicies(p *collectionPass) {
	if p.listErr != nil {
		c.rec.NotCollected(at("/policies"), p.listErr)
		return
	}
	type policyRead struct {
		row EndpointPolicyRow
		err error
	}
	reads := make([]policyRead, 0, len(p.computers))
	permissionDenied := false

	for _, e := range p.computers {
		read := policyRead{row: EndpointPolicyRow{Computer: e.Name}}
		if e.Policy != nil {
			read.row.PolicyID = e.Policy.ID
			read.row.PolicyName = e.Policy.Name
			read.row.Applied = e.Policy.Applied
		}
		if e.IsManaged != nil && !*e.IsManaged {
			// No agent, so no modules; GravityZone has no details for it.
			read.row.ModulesEnabled = []string{}
			reads = append(reads, read)
			continue
		}
		detail := p.details[e.ID]
		switch {
		case detail.err == nil:
			read.row.ModulesEnabled = enabledModuleNames(detail.detail.Modules)
		case componentsdk.Classify(detail.err) == componentsdk.CodePermissionDenied:
			permissionDenied = true
			read.err = detail.err
		default:
			p.diag.surfaceWarning("policies", "could not fetch detail for "+e.Name)
			read.err = detail.err
		}
		reads = append(reads, read)
	}

	sort.SliceStable(reads, func(i, j int) bool { return reads[i].row.Computer < reads[j].row.Computer })
	rows := make([]EndpointPolicyRow, len(reads))
	for i, read := range reads {
		rows[i] = read.row
		if read.err != nil {
			c.rec.NotCollected(at(fmt.Sprintf("/policies/per_endpoint/%d/modules_enabled", i)), read.err)
		}
	}
	p.posture.Policies = &Policies{PerEndpoint: rows}
	if p.adErr != nil {
		c.rec.Partial(at("/policies/per_endpoint"), 0, p.adErr)
	}

	if permissionDenied {
		p.diag.surfacePermissionDenied("policies", "Network")
	}
}

// enabledModuleNames returns the sorted names of modules reported enabled.
func enabledModuleNames(modules map[string]*bool) []string {
	names := make([]string, 0, len(modules))
	for name, enabled := range modules {
		if enabled != nil && *enabled {
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
	items, err := c.client.ListQuarantineItems(p.ctx)
	if err != nil {
		c.rec.NotCollected(at("/quarantine"), err)
		p.diag.surfaceFailed("quarantine", "Quarantine", "could not list quarantine items", err)
		return
	}

	q := &Quarantine{TotalCount: len(items)}
	p.posture.Quarantine = q
	if p.listErr != nil {
		// Rows are named by computer, which only the endpoint list knows.
		c.rec.NotCollected(at("/quarantine/per_computer"), p.listErr)
		return
	}

	nameByID := make(map[string]string, len(p.computers))
	for _, e := range p.computers {
		nameByID[e.ID] = e.Name
	}

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
			Date:         item.QuarantinedOn,
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
	if p.adErr != nil {
		// Items on computers only the Active Directory folder lists have no
		// computer name to go under.
		c.rec.Partial(at("/quarantine/per_computer"), 0, p.adErr)
	}
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
