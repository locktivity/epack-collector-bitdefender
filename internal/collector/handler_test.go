package collector

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

func TestRunFailsOnInvalidConfiguration(t *testing.T) {
	key := map[string]string{"BITDEFENDER_API_KEY": kitAPIKey}
	cases := []struct {
		name    string
		config  map[string]any
		secrets map[string]string
	}{
		{"no base_url", map[string]any{"level": "trust"}, key},
		{"base_url without https", map[string]any{"base_url": "http://gravityzone.example.com/api"}, key},
		{"base_url without a host", map[string]any{"base_url": "cloud.gravityzone.bitdefender.com/api"}, key},
		{"no API key", map[string]any{"base_url": kitBase}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runInProcess(t, tc.config, tc.secrets, nil)
			if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != componentsdk.CodeConfigInvalid {
				t.Fatalf("exit %d, failure %+v; want exit 2 with config_invalid", res.ExitCode, res.Failure)
			}
		})
	}
}

func TestRunRecordsTheSignedInPrincipal(t *testing.T) {
	res := runInProcess(t, map[string]any{"base_url": kitBase}, map[string]string{"BITDEFENDER_API_KEY": kitAPIKey}, kitResponses(kitCleanTenant()))
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	want := &componentsdk.Principal{Provider: "bitdefender-gravityzone", Kind: "api_key", Scopes: []string{"network", "quarantine"}}
	if !reflect.DeepEqual(res.Result.SignedInAs, want) {
		t.Errorf("signed_in_as = %+v, want %+v", res.Result.SignedInAs, want)
	}
}

func TestRunExits3WhenTheKeyIsRejected(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusOK} {
		responses := []collectortest.Response{{Method: http.MethodPost, URL: kitBase + "/v1.0/jsonrpc/general", Status: status, Body: kitRejectedKey}}
		res := runInProcess(t, map[string]any{"base_url": kitBase}, map[string]string{"BITDEFENDER_API_KEY": kitAPIKey}, responses)
		if res.ExitCode != 3 || res.Failure == nil || res.Failure.Code != componentsdk.CodeAuthFailed {
			t.Errorf("HTTP %d: exit %d, failure %+v; want exit 3 with auth_failed", status, res.ExitCode, res.Failure)
		}
	}
}

func TestRunFailsWhenTheParentGroupIsUnknown(t *testing.T) {
	responses := kitResponses(kitCleanTenant())
	for i := range responses {
		if responses[i].Operation == opEndpoints {
			responses[i].Body = gzError(-32002, "Resource not found", "There is no group with the specified ID")
		}
	}
	res := runInProcess(t, map[string]any{"base_url": kitBase, "parent_group_id": "5f3a8c2e9b1d4e0012345678"}, map[string]string{"BITDEFENDER_API_KEY": kitAPIKey}, responses)
	if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != componentsdk.CodeConfigInvalid {
		t.Fatalf("exit %d, failure %+v; want exit 2 with config_invalid", res.ExitCode, res.Failure)
	}
}

func TestRunRecordsListsPastTheReadCapAsTooLarge(t *testing.T) {
	cases := []struct {
		name     string
		level    string
		tenant   kitTenant
		pointers []string
	}{
		{"endpoints", "audit", kitFleetOverTheReadCap(), []string{"/scope/total_managed_computers", "/compliance/compliance_percentage", "/endpoints"}},
		{"quarantine", "internal", kitQuarantineOverTheReadCap(), []string{"/quarantine"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runInProcess(t, map[string]any{"base_url": kitBase, "level": tc.level}, map[string]string{"BITDEFENDER_API_KEY": kitAPIKey}, kitResponses(tc.tenant))
			if res.ExitCode != 0 || res.Result == nil {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			codes := map[string]componentsdk.Code{}
			for _, g := range res.Result.Gaps {
				if g.Path == artifactPath {
					codes[g.Pointer] = g.Code
				}
			}
			for _, pointer := range tc.pointers {
				if codes[pointer] != componentsdk.CodeTooLarge {
					t.Errorf("gap at %s has code %q, want too_large", pointer, codes[pointer])
				}
			}
		})
	}
}

// A denied call names the GravityZone API the key lacks, so the gap says
// what to enable.
func TestRunNamesTheMissingAPI(t *testing.T) {
	responses := answering(kitResponses(kitCleanTenant()), opInventory, kitADSearch, kitMissingNetworkAPI)
	res := runInProcess(t, map[string]any{"base_url": kitBase, "level": "audit"}, map[string]string{"BITDEFENDER_API_KEY": kitAPIKey}, responses)
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	found := false
	for _, g := range res.Result.Gaps {
		if g.Path == normalizedPath && g.Pointer == "/fleet" {
			found = true
			if g.Code != componentsdk.CodePermissionDenied || g.MissingPermission != "network" || g.Operation != opInventory {
				t.Errorf("fleet gap = %+v, want permission_denied on %s naming the network API", g, opInventory)
			}
		}
	}
	if !found {
		t.Error("no gap on the fleet")
	}
}

func runInProcess(t *testing.T, config map[string]any, secrets map[string]string, responses []collectortest.Response) componentsdk.InProcessResult {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	return componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    config,
		Secrets:   secrets,
		Transport: replay,
		Seed:      1,
		Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	})
}
