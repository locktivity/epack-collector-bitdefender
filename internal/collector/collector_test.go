package collector

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"
	"github.com/locktivity/epack/componentsdk"
)

// mockClient implements bdClient for tests, so no real GravityZone tenant
// is needed to exercise the collection logic.
type mockClient struct {
	signInErr error

	endpoints    []bitdefender.Endpoint
	endpointsErr error

	// adFolders are the Active Directory folders' IDs, and inventory the
	// endpoints below each one, by folder ID.
	adFolders    []string
	adFoldersErr error
	inventory    map[string][]bitdefender.Endpoint
	inventoryErr error
	inventoryIDs []string

	// details is keyed by endpoint ID.
	details    map[string]*bitdefender.EndpointDetail
	detailsErr error
	detailIDs  []string

	quarantine    []bitdefender.QuarantineItem
	quarantineErr error
}

func (m *mockClient) GetAPIKeyDetails(ctx context.Context) (*bitdefender.APIKeyDetails, error) {
	if m.signInErr != nil {
		return nil, m.signInErr
	}
	return &bitdefender.APIKeyDetails{EnabledAPIs: []string{"network", "quarantine"}}, nil
}

func (m *mockClient) ListEndpoints(ctx context.Context, parentID string, scanLogs bool) ([]bitdefender.Endpoint, error) {
	if m.endpointsErr != nil {
		return nil, m.endpointsErr
	}
	return m.endpoints, nil
}

func (m *mockClient) FindActiveDirectoryFolders(ctx context.Context) ([]string, error) {
	if m.adFoldersErr != nil {
		return nil, m.adFoldersErr
	}
	return m.adFolders, nil
}

func (m *mockClient) ListInventoryEndpoints(ctx context.Context, parentID string, scanLogs bool) ([]bitdefender.Endpoint, error) {
	m.inventoryIDs = append(m.inventoryIDs, parentID)
	if m.inventoryErr != nil {
		return nil, m.inventoryErr
	}
	return m.inventory[parentID], nil
}

func (m *mockClient) GetManagedEndpointDetails(ctx context.Context, endpointID string) (*bitdefender.EndpointDetail, error) {
	m.detailIDs = append(m.detailIDs, endpointID)
	if m.detailsErr != nil {
		return nil, m.detailsErr
	}
	if d, ok := m.details[endpointID]; ok {
		return d, nil
	}
	return &bitdefender.EndpointDetail{Modules: map[string]*bool{}}, nil
}

func (m *mockClient) ListQuarantineItems(ctx context.Context) ([]bitdefender.QuarantineItem, error) {
	if m.quarantineErr != nil {
		return nil, m.quarantineErr
	}
	return m.quarantine, nil
}

// healthyDetail is a getManagedEndpointDetails answer with an active license
// and current signatures, last seen at lastSeen, with modules on or off.
func healthyDetail(lastSeen string, modules map[string]bool) *bitdefender.EndpointDetail {
	flags := make(map[string]*bool, len(modules))
	for name, on := range modules {
		flags[name] = boolPtr(on)
	}
	return &bitdefender.EndpointDetail{
		LastSeen: lastSeen,
		Agent:    &bitdefender.EndpointAgent{Licensed: intPtr(bitdefender.LicenseActive), SignatureOutdated: boolPtr(false), ProductOutdated: boolPtr(false)},
		Modules:  flags,
	}
}

func managedComputer(id, name, os string, policy bitdefender.EndpointPolicy, outdated bool) bitdefender.Endpoint {
	return bitdefender.Endpoint{
		ID:                     id,
		Name:                   name,
		MachineType:            bitdefender.MachineTypeComputer,
		IsManaged:              boolPtr(true),
		OperatingSystemVersion: os,
		Policy:                 &policy,
		ProductOutdated:        boolPtr(outdated),
	}
}

// richMock returns a mock populated across every surface: three computers
// (two compliant, one not), one VM (out of scope), enabled modules for each
// computer, and two quarantine items.
func richMock() *mockClient {
	alice := managedComputer("ep-1", "alice-laptop", "Windows 11 Pro", bitdefender.EndpointPolicy{ID: "pol-1", Name: "Default Policy", Applied: boolPtr(true)}, false)
	alice.LastSuccessfulScan = &bitdefender.EndpointLastScan{Name: "Quick Scan", Date: "2026-06-30T09:00:00+00:00"}
	// Policy still pending and agent out of date.
	bob := managedComputer("ep-2", "bob-laptop", "macOS 15", bitdefender.EndpointPolicy{ID: "pol-1", Name: "Default Policy", Applied: boolPtr(false)}, true)
	bob.LastSuccessfulScan = &bitdefender.EndpointLastScan{Name: "Full Scan", Date: "2026-05-01T09:00:00+00:00"}
	carol := managedComputer("ep-3", "carol-laptop", "Windows 11 Pro", bitdefender.EndpointPolicy{ID: "pol-2", Name: "Engineering Policy", Applied: boolPtr(true)}, false)
	// Not a "computer": must be excluded from scope and compliance.
	vm := managedComputer("ep-4", "build-server-vm", "Ubuntu 24.04", bitdefender.EndpointPolicy{Applied: boolPtr(true)}, false)
	vm.MachineType = 2

	details := map[string]*bitdefender.EndpointDetail{
		"ep-1": healthyDetail("2026-06-30T09:15:00", map[string]bool{"antimalware": true, "edrSensor": true, "firewall": true, "deviceControl": false}),
		"ep-2": healthyDetail("2026-06-29T18:00:00", map[string]bool{"antimalware": true, "edrSensor": false, "firewall": false}),
		"ep-3": healthyDetail("2026-06-30T07:45:00", map[string]bool{"antimalware": true, "edrSensor": true, "advancedThreatControl": true}),
	}

	quarantine := []bitdefender.QuarantineItem{
		{
			ID:            "q-1",
			EndpointID:    "ep-2",
			ThreatName:    "Gen:Variant.Test.1",
			ActionStatus:  intPtr(1),
			QuarantinedOn: "2026-06-15T12:00:00",
			Details:       &bitdefender.QuarantineDetails{FilePath: `C:\Users\bob\Downloads\invoice.exe`},
		},
		{
			// Belongs to the out-of-scope VM; must be dropped, not emitted
			// under an empty/unknown computer name.
			ID:            "q-2",
			EndpointID:    "ep-4",
			ThreatName:    "Gen:Variant.Test.2",
			ActionStatus:  intPtr(1),
			QuarantinedOn: "2026-06-10T12:00:00",
		},
	}

	return &mockClient{endpoints: []bitdefender.Endpoint{alice, bob, carol, vm}, details: details, quarantine: quarantine}
}

func collectWith(t *testing.T, mock *mockClient, level componentsdk.Level) (*EndpointPosture, *componentsdk.Recorder) {
	t.Helper()
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{BaseURL: "https://example.invalid/api", APIKey: "test", Recorder: rec}, mock)
	posture, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("Collect(%s) error: %v", level, err)
	}
	return posture, rec
}

func collectAt(t *testing.T, level componentsdk.Level) *EndpointPosture {
	t.Helper()
	posture, _ := collectWith(t, richMock(), level)
	return posture
}

func gapAt(rec *componentsdk.Recorder, pointer string) (componentsdk.Gap, bool) {
	for _, g := range rec.Gaps() {
		if g.Path == artifactPath && g.Pointer == pointer {
			return g, true
		}
	}
	return componentsdk.Gap{}, false
}

func TestCollect_Trust(t *testing.T) {
	p := collectAt(t, componentsdk.LevelTrust)

	if p.CollectedAtLevel != "trust" {
		t.Errorf("collected_at_level = %q, want trust", p.CollectedAtLevel)
	}
	// Scope excludes the VM: 3 computers, not 4 endpoints.
	if p.Scope.TotalManagedComputers == nil || *p.Scope.TotalManagedComputers != 3 {
		t.Errorf("total_managed_computers = %v, want 3", p.Scope.TotalManagedComputers)
	}
	// alice (managed, applied, not outdated) and carol (same) are compliant;
	// bob (policy not applied, product outdated) is not.
	if p.Compliance.CompliantCount == nil || *p.Compliance.CompliantCount != 2 {
		t.Errorf("compliant_count = %v, want 2", p.Compliance.CompliantCount)
	}
	if p.Compliance.NonCompliantCount == nil || *p.Compliance.NonCompliantCount != 1 {
		t.Errorf("non_compliant_count = %v, want 1", p.Compliance.NonCompliantCount)
	}
	if p.Compliance.CompliancePercentage == nil || *p.Compliance.CompliancePercentage != round2(200.0/3.0) {
		t.Errorf("compliance_percentage = %v, want %v", p.Compliance.CompliancePercentage, round2(200.0/3.0))
	}
	if p.Endpoints != nil || p.Quarantine != nil || p.Policies != nil {
		t.Error("trust must not populate endpoints, quarantine, or policies")
	}
}

func TestCollect_Audit(t *testing.T) {
	p := collectAt(t, componentsdk.LevelAudit)

	if p.CollectedAtLevel != "audit" {
		t.Errorf("collected_at_level = %q, want audit", p.CollectedAtLevel)
	}
	if p.Endpoints == nil || len(p.Endpoints.PerEndpoint) != 3 {
		t.Fatalf("expected 3 endpoint rows, got %+v", p.Endpoints)
	}
	var sawBob bool
	for _, row := range p.Endpoints.PerEndpoint {
		if row.Name == "bob-laptop" {
			sawBob = true
			if row.Compliant == nil || *row.Compliant {
				t.Error("bob-laptop should not be compliant (policy not applied, product outdated)")
			}
			if row.PolicyApplied == nil || *row.PolicyApplied {
				t.Error("bob-laptop policy_applied should be false")
			}
			if row.ProductOutdated == nil || !*row.ProductOutdated {
				t.Error("bob-laptop product_outdated should be true")
			}
		}
		// Audit must not include last-scan (internal-only).
		if row.LastScanDate != "" || row.LastScanName != "" {
			t.Errorf("audit must not include last-scan detail, got %+v", row)
		}
	}
	if !sawBob {
		t.Error("expected bob-laptop in per-endpoint rows")
	}
	if p.Quarantine != nil || p.Policies != nil {
		t.Error("audit must not populate quarantine or policies (internal-only)")
	}
}

func TestCollect_Internal(t *testing.T) {
	p := collectAt(t, componentsdk.LevelInternal)

	if p.CollectedAtLevel != "internal" {
		t.Errorf("collected_at_level = %q, want internal", p.CollectedAtLevel)
	}

	// Endpoints gain last-scan detail.
	var sawAliceScan bool
	for _, row := range p.Endpoints.PerEndpoint {
		if row.Name == "alice-laptop" {
			sawAliceScan = true
			if row.LastScanDate == "" {
				t.Error("alice-laptop should have last_scan_date at internal")
			}
		}
	}
	if !sawAliceScan {
		t.Error("expected alice-laptop in per-endpoint rows")
	}

	// Policies: per-endpoint assignment + enabled modules.
	if p.Policies == nil || len(p.Policies.PerEndpoint) != 3 {
		t.Fatalf("expected 3 policy rows, got %+v", p.Policies)
	}
	for _, row := range p.Policies.PerEndpoint {
		if row.Computer == "carol-laptop" {
			if row.PolicyName != "Engineering Policy" {
				t.Errorf("carol-laptop policy_name = %q, want Engineering Policy", row.PolicyName)
			}
			foundATC := false
			for _, m := range row.ModulesEnabled {
				if m == "advancedThreatControl" {
					foundATC = true
				}
				if m == "deviceControl" {
					t.Error("deviceControl should not be listed as enabled for carol-laptop")
				}
			}
			if !foundATC {
				t.Error("expected advancedThreatControl in carol-laptop's enabled modules")
			}
		}
	}

	// Quarantine: grouped by computer, out-of-scope VM item dropped, full
	// path never emitted.
	if p.Quarantine == nil || p.Quarantine.TotalCount != 2 {
		t.Fatalf("expected quarantine.total_count = 2 (raw API count), got %+v", p.Quarantine)
	}
	if len(p.Quarantine.PerComputer) != 1 {
		t.Fatalf("expected 1 quarantine row (VM item dropped), got %d", len(p.Quarantine.PerComputer))
	}
	row := p.Quarantine.PerComputer[0]
	if row.Computer != "bob-laptop" {
		t.Errorf("quarantine row computer = %q, want bob-laptop", row.Computer)
	}
	if row.FileName != "invoice.exe" {
		t.Errorf("file_name = %q, want invoice.exe (basename only)", row.FileName)
	}
	if row.FilePathHash == "" {
		t.Error("expected a non-empty file_path_hash")
	}
	if row.Date != "2026-06-15T12:00:00" {
		t.Errorf("date = %q, want the item's quarantinedOn", row.Date)
	}
}

// A failed endpoint list leaves out everything built from it, with a gap,
// and the run still emits what it could read.
func TestCollect_EndpointListFailureLeavesValuesOut(t *testing.T) {
	mock := richMock()
	mock.endpointsErr = componentsdk.CodeError(componentsdk.CodeVendorError, errors.New("boom"))
	p, rec := collectWith(t, mock, componentsdk.LevelInternal)

	if p.Scope.TotalManagedComputers != nil || p.Compliance.CompliancePercentage != nil || p.Endpoints != nil || p.Policies != nil {
		t.Fatalf("values built from the endpoint list should be left out, got %+v", p)
	}
	for _, pointer := range []string{"/scope/total_managed_computers", "/compliance/compliance_percentage", "/compliance/compliant_count", "/compliance/non_compliant_count", "/endpoints", "/policies", "/quarantine/per_computer"} {
		if g, ok := gapAt(rec, pointer); !ok || g.Code != componentsdk.CodeVendorError {
			t.Errorf("gap at %s = %+v, want vendor_error", pointer, g)
		}
	}
	if p.Quarantine == nil || p.Quarantine.TotalCount != 2 {
		t.Errorf("quarantine total_count needs no endpoint list, got %+v", p.Quarantine)
	}
	if len(p.Diagnostics.Warnings) == 0 {
		t.Error("expected a warning diagnostic for the endpoint list")
	}
}

func TestCollect_DeniedDetailCallsLeaveModulesOut(t *testing.T) {
	mock := richMock()
	mock.detailsErr = componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("Network API not enabled"))
	p, rec := collectWith(t, mock, componentsdk.LevelInternal)

	if p.Policies == nil || len(p.Policies.PerEndpoint) != 3 {
		t.Fatalf("expected a policy row per computer, got %+v", p.Policies)
	}
	for i, row := range p.Policies.PerEndpoint {
		if row.ModulesEnabled != nil {
			t.Errorf("%s modules_enabled = %v, want it left out", row.Computer, row.ModulesEnabled)
		}
		if row.PolicyName == "" {
			t.Errorf("%s policy_name should come from the endpoint list", row.Computer)
		}
		if g, ok := gapAt(rec, fmt.Sprintf("/policies/per_endpoint/%d/modules_enabled", i)); !ok || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("row %d gap = %+v, want permission_denied", i, g)
		}
	}
	if len(p.Diagnostics.PermissionErrors) == 0 {
		t.Error("expected a permission_errors diagnostic when detail calls are denied")
	}
}

// A computer without the agent is non-compliant, gets no detail call, and
// enforces no modules.
func TestCollect_UnmanagedComputer(t *testing.T) {
	mock := richMock()
	mock.endpoints = append(mock.endpoints, bitdefender.Endpoint{ID: "ep-5", Name: "dave-desktop", MachineType: bitdefender.MachineTypeComputer, IsManaged: boolPtr(false)})
	p, rec := collectWith(t, mock, componentsdk.LevelInternal)

	if got := *p.Compliance.NonCompliantCount; got != 2 {
		t.Errorf("non_compliant_count = %d, want 2", got)
	}
	for _, id := range mock.detailIDs {
		if id == "ep-5" {
			t.Error("an unmanaged computer has no details to fetch")
		}
	}
	last := p.Policies.PerEndpoint[len(p.Policies.PerEndpoint)-1]
	if last.Computer != "dave-desktop" || last.ModulesEnabled == nil || len(last.ModulesEnabled) != 0 {
		t.Errorf("dave-desktop policy row = %+v, want an empty modules list", last)
	}
	for _, g := range rec.Gaps() {
		if g.Code != componentsdk.CodeUnsupported && g.Code != componentsdk.CodeNotRead {
			t.Errorf("an unmanaged computer leaves nothing out, got %+v", g)
		}
	}
}

// A managed computer whose row lacks productOutdated has unknown
// compliance, so the rollups are left out as partial.
func TestCollect_UnreportedAgentStateLeavesComplianceOut(t *testing.T) {
	mock := richMock()
	mock.endpoints[1].ProductOutdated = nil
	p, rec := collectWith(t, mock, componentsdk.LevelAudit)

	if p.Compliance.CompliancePercentage != nil || p.Compliance.CompliantCount != nil || p.Compliance.NonCompliantCount != nil {
		t.Fatalf("compliance = %+v, want it left out", p.Compliance)
	}
	if g, ok := gapAt(rec, "/compliance/compliance_percentage"); !ok || g.Status != componentsdk.GapPartial || g.Unmeasured != 1 {
		t.Errorf("compliance_percentage gap = %+v, want partial with 1 unmeasured", g)
	}
	for _, pointer := range []string{"/endpoints/per_endpoint/1/compliant", "/endpoints/per_endpoint/1/product_outdated"} {
		if g, ok := gapAt(rec, pointer); !ok || g.Code != componentsdk.CodeInvalidResponse {
			t.Errorf("gap at %s = %+v, want invalid_response", pointer, g)
		}
	}
}

func TestCollect_SignInFailureFailsTheRun(t *testing.T) {
	mock := richMock()
	mock.signInErr = componentsdk.CodeError(componentsdk.CodeAuthFailed, errors.New("rejected"))
	c := NewWithClient(Config{}, mock)
	if _, err := c.Collect(context.Background(), componentsdk.LevelTrust); componentsdk.Classify(err) != componentsdk.CodeAuthFailed {
		t.Fatalf("Collect() error = %v, want auth_failed", err)
	}
}

func TestCompliant(t *testing.T) {
	yes, no := boolPtr(true), boolPtr(false)
	tests := []struct {
		name string
		s    signals
		want *bool
	}{
		{"fully healthy", signals{managed: yes, policyApplied: yes, productOutdated: no}, yes},
		{"unmanaged", signals{managed: no}, no},
		{"policy pending", signals{managed: yes, policyApplied: no, productOutdated: no}, no},
		{"outdated agent", signals{managed: yes, policyApplied: yes, productOutdated: yes}, no},
		{"agent state unreported", signals{managed: yes, policyApplied: yes}, nil},
		{"management unreported", signals{policyApplied: yes, productOutdated: no}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.s.compliant()
			if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
				t.Errorf("compliant() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterComputers(t *testing.T) {
	in := []bitdefender.Endpoint{
		{ID: "1", MachineType: 1},
		{ID: "2", MachineType: 2},
		{ID: "3", MachineType: 3},
		{ID: "4", MachineType: 1},
	}
	out := filterComputers(in)
	if len(out) != 2 {
		t.Fatalf("filterComputers() returned %d, want 2", len(out))
	}
	for _, e := range out {
		if e.MachineType != bitdefender.MachineTypeComputer {
			t.Errorf("unexpected machineType %d in filtered output", e.MachineType)
		}
	}
}

// adMock is richMock with an Active Directory folder that holds erin-laptop,
// which only the folder lists, and alice-laptop, which getEndpointsList
// lists too.
func adMock() *mockClient {
	m := richMock()
	erin := managedComputer("ep-6", "erin-laptop", "Windows 11 Enterprise", bitdefender.EndpointPolicy{ID: "pol-2", Name: "Engineering Policy", Applied: boolPtr(true)}, false)
	aliceAgain := m.endpoints[0]
	aliceAgain.OperatingSystemVersion = "Windows 11 Pro for Workstations"
	m.adFolders = []string{"ad-1"}
	m.inventory = map[string][]bitdefender.Endpoint{"ad-1": {erin, aliceAgain}}
	m.details["ep-6"] = healthyDetail("2026-06-30T11:20:00", map[string]bool{"antimalware": true, "edrSensor": true})
	return m
}

func TestCollect_CountsActiveDirectoryComputersOnce(t *testing.T) {
	mock := adMock()
	p, _ := collectWith(t, mock, componentsdk.LevelAudit)

	if got := *p.Scope.TotalManagedComputers; got != 4 {
		t.Errorf("total_managed_computers = %d, want 4 with erin-laptop and alice-laptop once", got)
	}
	if len(p.Endpoints.PerEndpoint) != 4 {
		t.Fatalf("endpoint rows = %d, want 4", len(p.Endpoints.PerEndpoint))
	}
	if os := p.Endpoints.PerEndpoint[0].OperatingSystem; os != "Windows 11 Pro" {
		t.Errorf("alice-laptop's OS = %q, want the getEndpointsList row's", os)
	}
	n := p.Normalized()
	if *n.Fleet.DeviceCount != 4 || *n.Scope.ObservedDeviceCount != 5 {
		t.Errorf("device_count = %d and observed_device_count = %d, want 4 computers of 5 endpoints", *n.Fleet.DeviceCount, *n.Scope.ObservedDeviceCount)
	}
	if !reflect.DeepEqual(mock.inventoryIDs, []string{"ad-1"}) {
		t.Errorf("listed the inventory under %v, want the Active Directory folder", mock.inventoryIDs)
	}
}

func TestCollect_ListsTheConfiguredGroupInTheInventory(t *testing.T) {
	mock := adMock()
	mock.adFoldersErr = errors.New("the folder search must not run with parent_group_id")
	mock.inventory["grp-9"] = mock.inventory["ad-1"]
	rec := &componentsdk.Recorder{}
	c := NewWithClient(Config{BaseURL: "https://example.invalid/api", APIKey: "test", ParentGroupID: "grp-9", Recorder: rec}, mock)
	p, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mock.inventoryIDs, []string{"grp-9"}) {
		t.Errorf("listed the inventory under %v, want the configured group", mock.inventoryIDs)
	}
	if got := *p.Scope.TotalManagedComputers; got != 4 {
		t.Errorf("total_managed_computers = %d, want 4", got)
	}
}

// A failed read of the Active Directory folder leaves the fleet counts out
// and keeps the rows getEndpointsList gave.
func TestCollect_ActiveDirectoryFailureLeavesTheCountsOut(t *testing.T) {
	mock := adMock()
	mock.inventoryErr = componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("Network API not enabled"))
	p, rec := collectWith(t, mock, componentsdk.LevelAudit)

	if p.Scope.TotalManagedComputers != nil || p.Compliance.CompliantCount != nil {
		t.Errorf("counts = %+v %+v, want them left out", p.Scope, p.Compliance)
	}
	if len(p.Endpoints.PerEndpoint) != 3 {
		t.Errorf("endpoint rows = %d, want the 3 getEndpointsList computers", len(p.Endpoints.PerEndpoint))
	}
	if g, ok := gapAt(rec, "/endpoints/per_endpoint"); !ok || g.Status != componentsdk.GapPartial || g.Code != componentsdk.CodePermissionDenied {
		t.Errorf("rows gap = %+v, want partial permission_denied", g)
	}
	n := p.Normalized()
	if n.Scope.DiscoveryComplete != nil || n.Fleet != nil || n.Protection != nil {
		t.Errorf("normalized = %+v, want discovery unknown with no fleet or protection", n)
	}
	if n.Devices == nil || len(*n.Devices) != 3 {
		t.Errorf("device rows = %v, want the 3 getEndpointsList computers", n.Devices)
	}
	for _, pointer := range []string{"/fleet", "/protection", "/scope/observed_device_count", "/scope/discovery_complete"} {
		if g, ok := normalizedGapAt(rec, pointer); !ok || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("gap at %s = %+v, want permission_denied", pointer, g)
		}
	}
}

func normalizedGapAt(rec *componentsdk.Recorder, pointer string) (componentsdk.Gap, bool) {
	for _, g := range rec.Gaps() {
		if g.Path == normalizedPath && g.Pointer == pointer {
			return g, true
		}
	}
	return componentsdk.Gap{}, false
}

func pctValue(t *testing.T, p Percentage) float64 {
	t.Helper()
	if !p.Read || p.Value == nil {
		t.Fatalf("percentage = %+v, want a value", p)
	}
	return *p.Value
}

// An unmanaged computer has no modules and counts against each percentage.
// An expired license and outdated signatures each make antimalware
// unhealthy.
func TestCollect_ProtectionPercentages(t *testing.T) {
	mock := richMock()
	mock.endpoints = append(mock.endpoints, bitdefender.Endpoint{ID: "ep-5", Name: "dave-desktop", MachineType: bitdefender.MachineTypeComputer, IsManaged: boolPtr(false), OperatingSystemVersion: "Windows 10 Pro"})
	mock.details["ep-2"].Agent.SignatureOutdated = boolPtr(true)
	mock.details["ep-3"].Agent.Licensed = intPtr(2)
	p, _ := collectWith(t, mock, componentsdk.LevelTrust)
	n := p.Normalized()

	if got := pctValue(t, n.Protection.AntimalwareInstalledPct); got != 75 {
		t.Errorf("antimalware_installed_pct = %v, want 75 (3 of 4)", got)
	}
	if got := pctValue(t, n.Protection.AntimalwareHealthyPct); got != 25 {
		t.Errorf("antimalware_healthy_pct = %v, want 25 (only alice-laptop)", got)
	}
	if got := pctValue(t, n.Protection.EDRInstalledPct); got != 50 {
		t.Errorf("edr_installed_pct = %v, want 50 (alice-laptop and carol-laptop)", got)
	}
	if n.Fleet.DeviceCount != nil || n.MetricCoverage != nil || n.Devices != nil || n.Scope.ObservedDeviceCount != nil {
		t.Errorf("a trust run must leave out the counts and rows, got %+v", n)
	}
	if !*n.Fleet.DevicesPresent {
		t.Error("devices_present = false, want true")
	}
}

// A computer whose details could not be read is never counted, so the
// percentages are left out with the call's code.
func TestCollect_DeniedDetailCallLeavesProtectionOut(t *testing.T) {
	mock := richMock()
	mock.detailsErr = componentsdk.CodeError(componentsdk.CodePermissionDenied, errors.New("Network API not enabled"))
	p, rec := collectWith(t, mock, componentsdk.LevelAudit)
	n := p.Normalized()

	if n.Protection != nil || len(n.MetricCoverage) != 0 {
		t.Errorf("protection = %+v and coverage = %+v, want both left out", n.Protection, n.MetricCoverage)
	}
	for _, m := range protectionMetrics {
		g, ok := normalizedGapAt(rec, m.pointer)
		if !ok || g.Code != componentsdk.CodePermissionDenied || g.Status != componentsdk.GapPartial || g.Unmeasured != 3 {
			t.Errorf("gap at %s = %+v, want partial permission_denied over 3 computers", m.pointer, g)
		}
	}
	if *n.Fleet.DeviceCount != 3 {
		t.Errorf("device_count = %d, want 3", *n.Fleet.DeviceCount)
	}
}

// A computer whose details send a module as null, or leave out the license,
// has an unknown reading for each percentage that needs it. Those
// percentages are left out with a partial gap over those computers, and
// metric_coverage counts them as unknown. A percentage every computer has a
// reading for stays.
func TestCollect_UnreportedReadingsLeaveThePercentageOut(t *testing.T) {
	mock := richMock()
	mock.details["ep-2"].Agent.Licensed = nil
	mock.details["ep-3"].Modules["antimalware"] = nil
	p, rec := collectWith(t, mock, componentsdk.LevelAudit)
	n := p.Normalized()

	for _, tc := range []struct {
		metric     string
		pct        Percentage
		unmeasured int
		coverage   MetricCoverage
	}{
		{"protection.antimalware_installed_pct", n.Protection.AntimalwareInstalledPct, 1, MetricCoverage{Passing: 2, Unknown: 1}},
		{"protection.antimalware_healthy_pct", n.Protection.AntimalwareHealthyPct, 2, MetricCoverage{Passing: 1, Unknown: 2}},
	} {
		if tc.pct.Read {
			t.Errorf("%s = %+v, want it left out", tc.metric, tc.pct)
		}
		g, ok := normalizedGapAt(rec, "/"+strings.ReplaceAll(tc.metric, ".", "/"))
		if !ok || g.Status != componentsdk.GapPartial || g.Code != componentsdk.CodeInvalidResponse || g.Unmeasured != tc.unmeasured {
			t.Errorf("gap at %s = %+v, want partial invalid_response over %d computers", tc.metric, g, tc.unmeasured)
		}
		if got := n.MetricCoverage[tc.metric]; got != tc.coverage {
			t.Errorf("metric_coverage[%s] = %+v, want %+v", tc.metric, got, tc.coverage)
		}
	}
	if got := pctValue(t, n.Protection.EDRInstalledPct); got != 66 {
		t.Errorf("edr_installed_pct = %v, want 66 (2 of 3)", got)
	}
	if g, ok := normalizedGapAt(rec, "/protection/edr_installed_pct"); ok {
		t.Errorf("edr_installed_pct has gap %+v, want none", g)
	}
}

// discovery_complete is true for lists read in full and false for a list
// longer than the collector reads. A failed call leaves it null with the
// call's gap.
func TestCollect_DiscoveryComplete(t *testing.T) {
	tooLarge := componentsdk.CodeError(componentsdk.CodeTooLarge, errors.New("more than the collector reads"))
	vendorError := componentsdk.CodeError(componentsdk.CodeVendorError, errors.New("boom"))
	for _, tc := range []struct {
		name    string
		mock    func(*mockClient)
		want    *bool
		wantGap componentsdk.Code
	}{
		{"read in full", func(*mockClient) {}, boolPtr(true), ""},
		{"endpoint list past the cap", func(m *mockClient) { m.endpointsErr = tooLarge }, boolPtr(false), ""},
		{"Active Directory folder past the cap", func(m *mockClient) { m.inventoryErr = tooLarge }, boolPtr(false), ""},
		{"endpoint list failed", func(m *mockClient) { m.endpointsErr = vendorError }, nil, componentsdk.CodeVendorError},
		{"Active Directory search failed", func(m *mockClient) { m.adFoldersErr = vendorError }, nil, componentsdk.CodeVendorError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := adMock()
			tc.mock(mock)
			p, rec := collectWith(t, mock, componentsdk.LevelAudit)
			got := p.Normalized().Scope.DiscoveryComplete
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Errorf("discovery_complete = %v, want %v", got, tc.want)
			}
			g, ok := normalizedGapAt(rec, "/scope/discovery_complete")
			if tc.wantGap == "" && ok {
				t.Errorf("discovery_complete has gap %+v, want none", g)
			}
			if tc.wantGap != "" && (!ok || g.Code != tc.wantGap) {
				t.Errorf("discovery_complete gap = %+v, want %s", g, tc.wantGap)
			}
		})
	}
}

// Disk encryption is in a report the collector does not read, so its gap
// and its availability reason are not_read. The values GravityZone's API
// does not report are unsupported. Each availability reason matches the
// gap code.
func TestCollect_UnreadValueCodes(t *testing.T) {
	p, rec := collectWith(t, richMock(), componentsdk.LevelAudit)
	n := p.Normalized()
	want := map[string]componentsdk.Code{
		"/hardening/disk_encryption_pct":       componentsdk.CodeNotRead,
		"/hardening/firewall_enabled_pct":      componentsdk.CodeUnsupported,
		"/hardening/screen_lock_compliant_pct": componentsdk.CodeUnsupported,
		"/protection/edr_healthy_pct":          componentsdk.CodeUnsupported,
		"/compliance/compliant_pct":            componentsdk.CodeUnsupported,
		"/patching/unsupported_os_count":       componentsdk.CodeUnsupported,
	}
	for pointer, code := range want {
		if g, ok := normalizedGapAt(rec, pointer); !ok || g.Code != code {
			t.Errorf("gap at %s = %+v, want %s", pointer, g, code)
		}
	}
	reasons := map[string]string{}
	for _, a := range n.Availability {
		reasons[a.Path] = a.Reason
	}
	if got := reasons["hardening.disk_encryption_pct"]; got != reasonNotRead {
		t.Errorf("disk encryption availability reason = %q, want not_read", got)
	}
	if got := reasons["hardening.firewall_enabled_pct"]; got != reasonUnsupported {
		t.Errorf("firewall availability reason = %q, want unsupported", got)
	}
	for _, u := range unreadValues {
		if u.path == "" {
			continue
		}
		if g, _ := normalizedGapAt(rec, u.pointer); reasons[u.path] != string(g.Code) {
			t.Errorf("%s availability reason = %q, want its gap code %q", u.path, reasons[u.path], g.Code)
		}
	}
}

func TestCollect_EmptyCompanyHasNullPercentages(t *testing.T) {
	p, _ := collectWith(t, &mockClient{}, componentsdk.LevelAudit)
	n := p.Normalized()
	if *n.Fleet.DevicesPresent || *n.Fleet.DeviceCount != 0 {
		t.Errorf("fleet = %+v, want no devices", n.Fleet)
	}
	for _, pct := range []Percentage{n.Protection.AntimalwareInstalledPct, n.Protection.AntimalwareHealthyPct, n.Protection.EDRInstalledPct} {
		if !pct.Read || pct.Value != nil {
			t.Errorf("percentage = %+v, want null", pct)
		}
	}
	if n.Devices == nil || len(*n.Devices) != 0 {
		t.Errorf("devices = %v, want an empty list", n.Devices)
	}
}

func TestAntimalwareHealthy(t *testing.T) {
	agent := func(licensed *int, outdated *bool) *bitdefender.EndpointAgent {
		return &bitdefender.EndpointAgent{Licensed: licensed, SignatureOutdated: outdated}
	}
	active, expired, pending, none := intPtr(1), intPtr(2), intPtr(0), intPtr(6)
	current, outdated := boolPtr(false), boolPtr(true)
	on, off := controlReading{state: statePass}, controlReading{state: stateFail}
	null := controlReading{state: stateUnknown, unread: "modules.antimalware"}
	tests := []struct {
		name        string
		antimalware controlReading
		agent       *bitdefender.EndpointAgent
		want        controlReading
	}{
		{"on, active license, current signatures", on, agent(active, current), on},
		{"module off or not installed", off, agent(active, current), off},
		{"expired license", on, agent(expired, current), off},
		{"license pending authentication", on, agent(pending, current), off},
		{"no license", on, agent(none, current), off},
		{"outdated signatures", on, agent(active, outdated), off},
		{"no agent state", on, nil, controlReading{state: stateUnknown, unread: "agent"}},
		{"license not reported", on, agent(nil, current), controlReading{state: stateUnknown, unread: "agent.licensed"}},
		{"signatures not reported", on, agent(active, nil), controlReading{state: stateUnknown, unread: "agent.signatureOutdated"}},
		{"module off and no agent state", off, nil, off},
		{"module sent as null", null, agent(active, current), null},
		{"module sent as null and license expired", null, agent(expired, current), off},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := antimalwareHealthy(tt.antimalware, tt.agent); got != tt.want {
				t.Errorf("antimalwareHealthy() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// modules lists the modules installed on a computer, so a module it leaves
// out is not installed. A module sent as null is unknown.
func TestModuleState(t *testing.T) {
	modules := map[string]*bool{"antimalware": boolPtr(true), "edrSensor": boolPtr(false), "firewall": nil}
	for name, want := range map[string]controlReading{
		"antimalware":   {state: statePass},
		"edrSensor":     {state: stateFail},
		"firewall":      {state: stateUnknown, unread: "modules.firewall"},
		"deviceControl": {state: stateFail},
	} {
		if got := moduleState(modules, name); got != want {
			t.Errorf("moduleState(%s) = %+v, want %+v", name, got, want)
		}
	}
}

func TestOSFamily(t *testing.T) {
	for name, want := range map[string]string{
		"Windows 11 Pro":             "windows",
		"Windows Server 2022":        "windows",
		"macOS 15":                   "macos",
		"Mac OS X 10.15":             "macos",
		"Ubuntu 24.04":               "linux",
		"Red Hat Enterprise Linux 9": "linux",
		"Amazon Linux 2023":          "linux",
		"":                           "unknown",
		"FreeBSD 14":                 "other",
	} {
		if got := osFamily(name); got != want {
			t.Errorf("osFamily(%q) = %s, want %s", name, got, want)
		}
	}
}

func TestLastSeenAt(t *testing.T) {
	for raw, want := range map[string]string{
		"2026-08-22T13:46:59":       "2026-08-22T13:46:59Z",
		"2026-08-22T13:46:59+02:00": "2026-08-22T11:46:59Z",
	} {
		if got, ok := lastSeenAt(raw); !ok || got != want {
			t.Errorf("lastSeenAt(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
	if _, ok := lastSeenAt("22/08/2026"); ok {
		t.Error("lastSeenAt read a date it should reject")
	}
}

func TestMergeEndpoints(t *testing.T) {
	listed := []bitdefender.Endpoint{{ID: "ep-1", Name: "listed"}, {ID: "ep-2"}}
	inventory := []bitdefender.Endpoint{{ID: "ep-1", Name: "inventory"}, {ID: "ep-3"}, {ID: "ep-3"}}
	got := mergeEndpoints(listed, inventory)
	if len(got) != 3 || got[0].Name != "listed" || got[2].ID != "ep-3" {
		t.Errorf("mergeEndpoints() = %+v, want ep-1 from getEndpointsList, ep-2, and ep-3 once", got)
	}
}
