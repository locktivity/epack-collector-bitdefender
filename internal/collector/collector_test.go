package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"
	"github.com/locktivity/epack/componentsdk"
)

// mockClient implements bdClient for tests, so no real GravityZone tenant
// is needed to exercise the collection logic.
type mockClient struct {
	endpoints    []bitdefender.Endpoint
	endpointsErr error

	// details is keyed by endpoint ID.
	details    map[string]*bitdefender.EndpointDetail
	detailsErr error

	quarantine    []bitdefender.QuarantineItem
	quarantineErr error
}

func (m *mockClient) ListEndpoints(ctx context.Context, parentID string) ([]bitdefender.Endpoint, error) {
	if m.endpointsErr != nil {
		return nil, m.endpointsErr
	}
	return m.endpoints, nil
}

func (m *mockClient) GetManagedEndpointDetails(ctx context.Context, endpointID string) (*bitdefender.EndpointDetail, error) {
	if m.detailsErr != nil {
		return nil, m.detailsErr
	}
	if d, ok := m.details[endpointID]; ok {
		return d, nil
	}
	return &bitdefender.EndpointDetail{}, nil
}

func (m *mockClient) ListQuarantineItems(ctx context.Context) ([]bitdefender.QuarantineItem, error) {
	if m.quarantineErr != nil {
		return nil, m.quarantineErr
	}
	return m.quarantine, nil
}

// richMock returns a mock populated across every surface: three computers
// (two compliant, one not), one VM (out of scope), a policy assignment and
// enabled modules for each computer, and one quarantine item.
func richMock() *mockClient {
	endpoints := []bitdefender.Endpoint{
		{
			ID:                     "ep-1",
			Name:                   "alice-laptop",
			MachineType:            bitdefender.MachineTypeComputer,
			IsManaged:              true,
			OperatingSystemVersion: "Windows 11 Pro",
			Policy:                 bitdefender.EndpointPolicy{ID: "pol-1", Name: "Default Policy", Applied: true},
			ProductOutdated:        false,
			LastSuccessfulScan:     &bitdefender.EndpointLastScan{Name: "Quick Scan", Date: "2026-06-30T09:00:00+00:00"},
		},
		{
			ID:                     "ep-2",
			Name:                   "bob-laptop",
			MachineType:            bitdefender.MachineTypeComputer,
			IsManaged:              true,
			OperatingSystemVersion: "macOS 15",
			Policy:                 bitdefender.EndpointPolicy{ID: "pol-1", Name: "Default Policy", Applied: false}, // pending
			ProductOutdated:        true,
			LastSuccessfulScan:     &bitdefender.EndpointLastScan{Name: "Full Scan", Date: "2026-05-01T09:00:00+00:00"},
		},
		{
			ID:                     "ep-3",
			Name:                   "carol-laptop",
			MachineType:            bitdefender.MachineTypeComputer,
			IsManaged:              true,
			OperatingSystemVersion: "Windows 11 Pro",
			Policy:                 bitdefender.EndpointPolicy{ID: "pol-2", Name: "Engineering Policy", Applied: true},
			ProductOutdated:        false,
		},
		{
			// Not a "computer": must be excluded from scope and compliance.
			ID:           "ep-4",
			Name:         "build-server-vm",
			MachineType:  2, // virtual machine
			IsManaged:    true,
			Policy:       bitdefender.EndpointPolicy{Applied: true},
		},
	}

	details := map[string]*bitdefender.EndpointDetail{
		"ep-1": {
			Policy:  bitdefender.EndpointPolicy{ID: "pol-1", Name: "Default Policy", Applied: true},
			Modules: map[string]bool{"antimalware": true, "firewall": true, "deviceControl": false},
		},
		"ep-2": {
			Policy:  bitdefender.EndpointPolicy{ID: "pol-1", Name: "Default Policy", Applied: false},
			Modules: map[string]bool{"antimalware": true, "firewall": false},
		},
		"ep-3": {
			Policy:  bitdefender.EndpointPolicy{ID: "pol-2", Name: "Engineering Policy", Applied: true},
			Modules: map[string]bool{"antimalware": true, "advancedThreatControl": true},
		},
	}

	quarantine := []bitdefender.QuarantineItem{
		{
			ID:           "q-1",
			EndpointID:   "ep-2",
			ThreatName:   "Gen:Variant.Test.1",
			ActionStatus: 1,
			Date:         "2026-06-15T12:00:00+00:00",
			Details:      &bitdefender.QuarantineDetails{FilePath: `C:\Users\bob\Downloads\invoice.exe`},
		},
		{
			// Belongs to the out-of-scope VM; must be dropped, not emitted
			// under an empty/unknown computer name.
			ID:           "q-2",
			EndpointID:   "ep-4",
			ThreatName:   "Gen:Variant.Test.2",
			ActionStatus: 1,
			Date:         "2026-06-10T12:00:00+00:00",
		},
	}

	return &mockClient{endpoints: endpoints, details: details, quarantine: quarantine}
}

func collectAt(t *testing.T, level componentsdk.Level) *EndpointPosture {
	t.Helper()
	c := NewWithClient(Config{BaseURL: "https://example.invalid/api", APIKey: "test"}, richMock())
	posture, err := c.Collect(context.Background(), level)
	if err != nil {
		t.Fatalf("Collect(%s) error: %v", level, err)
	}
	return posture
}

func TestCollect_Trust(t *testing.T) {
	p := collectAt(t, componentsdk.LevelTrust)

	if p.CollectedAtLevel != "trust" {
		t.Errorf("collected_at_level = %q, want trust", p.CollectedAtLevel)
	}
	// Scope excludes the VM: 3 computers, not 4 endpoints.
	if p.Scope.TotalManagedComputers != 3 {
		t.Errorf("total_managed_computers = %d, want 3", p.Scope.TotalManagedComputers)
	}
	// alice (managed, applied, not outdated) and carol (same) are compliant;
	// bob (policy not applied, product outdated) is not.
	if p.Compliance.CompliantCount != 2 {
		t.Errorf("compliant_count = %d, want 2", p.Compliance.CompliantCount)
	}
	if p.Compliance.NonCompliantCount != 1 {
		t.Errorf("non_compliant_count = %d, want 1", p.Compliance.NonCompliantCount)
	}
	wantPct := 200.0 / 3.0
	if diff := p.Compliance.CompliancePercentage - round2(wantPct); diff > 0.01 || diff < -0.01 {
		t.Errorf("compliance_percentage = %v, want ~%v", p.Compliance.CompliancePercentage, round2(wantPct))
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
			if row.Compliant {
				t.Error("bob-laptop should not be compliant (policy not applied, product outdated)")
			}
			if row.PolicyApplied {
				t.Error("bob-laptop policy_applied should be false")
			}
			if !row.ProductOutdated {
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
}

func TestCollect_EndpointListFailureIsFatal(t *testing.T) {
	c := NewWithClient(Config{BaseURL: "x", APIKey: "x"}, &mockClient{endpointsErr: errors.New("boom")})
	if _, err := c.Collect(context.Background(), componentsdk.LevelTrust); err == nil {
		t.Fatal("expected an error when the endpoint list call fails")
	}
}

func TestCollect_PolicyDetailFailureDegradesGracefully(t *testing.T) {
	mock := richMock()
	mock.detailsErr = bitdefender.ErrPermissionDenied
	c := NewWithClient(Config{BaseURL: "x", APIKey: "x"}, mock)

	p, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	if p.Policies == nil || len(p.Policies.PerEndpoint) != 3 {
		t.Fatalf("expected policy rows to fall back to list-level assignment, got %+v", p.Policies)
	}
	if len(p.Diagnostics.PermissionErrors) == 0 {
		t.Error("expected a permission_errors diagnostic when detail calls are denied")
	}
}

func TestIsCompliant(t *testing.T) {
	tests := []struct {
		name string
		e    bitdefender.Endpoint
		want bool
	}{
		{"fully healthy", bitdefender.Endpoint{IsManaged: true, Policy: bitdefender.EndpointPolicy{Applied: true}, ProductOutdated: false}, true},
		{"unmanaged", bitdefender.Endpoint{IsManaged: false, Policy: bitdefender.EndpointPolicy{Applied: true}, ProductOutdated: false}, false},
		{"policy pending", bitdefender.Endpoint{IsManaged: true, Policy: bitdefender.EndpointPolicy{Applied: false}, ProductOutdated: false}, false},
		{"outdated agent", bitdefender.Endpoint{IsManaged: true, Policy: bitdefender.EndpointPolicy{Applied: true}, ProductOutdated: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCompliant(tt.e); got != tt.want {
				t.Errorf("isCompliant() = %v, want %v", got, tt.want)
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
