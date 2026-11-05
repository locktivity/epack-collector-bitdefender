package collector

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitRejectedKey is GravityZone's authorization error for a key it does not
// accept.
var kitRejectedKey = gzError(-32001, "Authorization error", "The API key is not valid")

// kitMissingNetworkAPI is GravityZone's authorization error for a key that
// lacks the Network API.
var kitMissingNetworkAPI = gzError(-32001, "Authorization error", "API Key is not allowed to access the selected API: Network")

// kitNow is the time the kit's runs see.
var kitNow = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

// kitADSearch is in the request body pin of the search for the Active
// Directory folder, and in no other.
const kitADSearch = `"name":"Active Directory"`

// gravityZoneFaults inject failures in GravityZone's own form: JSON-RPC
// errors in an HTTP 200 body, and its 401, 403, and 429 responses, which
// carry a JSON-RPC error too. A throttle or a server error in a 200 that
// clears on retry must change nothing.
func gravityZoneFaults() []collectortest.Fault {
	throttle := gzError(-32003, "Too many requests", "Rate limit exceeded. Maximum 100 requests per 60 seconds allowed. Try again later.")
	serverError := gzError(-32000, "Server error", "An unexpected error occurred")
	retryAfter := http.Header{"Retry-After": []string{"1"}}

	surfaceAuthorization := collectortest.BodyFault("rpc-authorization", kitMissingNetworkAPI, componentsdk.CodePermissionDenied)
	surfaceAuthorization.Operations = []string{opEndpoints, opInventory, opDetails, opQuarantine}
	signInAuthorization := collectortest.BodyFault("rpc-authorization-at-sign-in", kitRejectedKey, componentsdk.CodeAuthFailed)
	signInAuthorization.Operations = []string{opSignIn}
	serverErrorOnce := collectortest.BodyFault("rpc-server-error-once", serverError, "")
	serverErrorOnce.Transient = true
	throttleOnce := collectortest.BodyFault("rpc-too-many-requests-once", throttle, "")
	throttleOnce.Transient = true

	return []collectortest.Fault{
		collectortest.StatusFault("gz-401", http.StatusUnauthorized, nil, kitRejectedKey, componentsdk.CodeAuthFailed, false),
		collectortest.StatusFault("gz-403", http.StatusForbidden, nil, kitMissingNetworkAPI, componentsdk.CodePermissionDenied, false),
		surfaceAuthorization,
		signInAuthorization,
		collectortest.BodyFault("rpc-invalid-params", gzError(-32602, "Invalid params", "Invalid parameter: perPage"), componentsdk.CodeInvalidResponse),
		serverErrorOnce,
		collectortest.BodyFault("rpc-server-error", serverError, componentsdk.CodeVendorError),
		collectortest.StatusFault("gz-429-once", http.StatusTooManyRequests, retryAfter, throttle, "", true),
		collectortest.StatusFault("gz-429", http.StatusTooManyRequests, retryAfter, throttle, componentsdk.CodeRateLimited, false),
		throttleOnce,
		collectortest.BodyFault("rpc-too-many-requests", throttle, componentsdk.CodeRateLimited),
	}
}

// answering returns responses with each answer of op whose request body
// pin contains match replaced by body. An empty match replaces every answer
// of op.
func answering(responses []collectortest.Response, op, match, body string) []collectortest.Response {
	out := make([]collectortest.Response, len(responses))
	copy(out, responses)
	for i := range out {
		if out[i].Operation == op && strings.Contains(out[i].RequestBody, match) {
			out[i].Body = body
		}
	}
	return out
}

func TestCollectorKit(t *testing.T) {
	clean := kitResponses(kitCleanTenant())
	noFolder := kitResult(inventoryPage([]map[string]any{{"id": "grp-ad-servers", "name": "Active Directory Servers", "type": 4}}, 1, 1, 1))
	collectortest.Run(t, collectortest.Suite{
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  map[string]any{"base_url": kitBase, "level": "internal"},
		Secrets: map[string]string{"BITDEFENDER_API_KEY": kitAPIKey},
		Clock:   kitNow,
		Scenarios: []collectortest.Scenario{
			{
				// Endpoints of every machine type, over both pages of
				// endpoints, both pages of the Active Directory folder, and
				// both pages of quarantined items. alice-laptop is in both
				// lists and counts once. The counts cover bob-laptop's
				// outdated agent and signatures, erin-laptop's expired
				// license, dave-desktop without the agent, each computer's
				// own modules, and the quarantine date.
				Name:      "clean",
				Responses: clean,
				Expect: map[string]map[string]any{
					artifactPath: {
						"/scope/total_managed_computers":             5,
						"/compliance/compliant_count":                3,
						"/compliance/non_compliant_count":            2,
						"/compliance/compliance_percentage":          60,
						"/endpoints/per_endpoint/1/product_outdated": true,
						"/endpoints/per_endpoint/3/compliant":        false,
						"/endpoints/per_endpoint/4/name":             "erin-laptop",
						"/policies/per_endpoint/0/modules_enabled":   []string{"antimalware", "edrSensor", "firewall"},
						"/policies/per_endpoint/1/modules_enabled":   []string{"antimalware"},
						"/policies/per_endpoint/2/modules_enabled":   []string{"advancedThreatControl", "antimalware", "edrSensor"},
						"/policies/per_endpoint/3/modules_enabled":   []string{},
						"/quarantine/total_count":                    4,
						"/quarantine/per_computer/1/date":            "2026-06-20T08:30:00",
						"/quarantine/per_computer/2/computer":        "erin-laptop",
					},
					normalizedPath: {
						"/collected_at":                         "2026-07-01T00:00:00Z",
						"/scope/discovery_complete":             true,
						"/scope/observed_device_count":          8,
						"/fleet/devices_present":                true,
						"/fleet/device_count":                   5,
						"/fleet/managed_device_count":           4,
						"/fleet/devices_by_os":                  map[string]any{"windows": 4, "macos": 1},
						"/protection/antimalware_installed_pct": 80,
						"/protection/antimalware_healthy_pct":   40,
						"/protection/edr_installed_pct":         60,
						"/protection/edr_healthy_pct":           collectortest.Absent,
						"/hardening":                            collectortest.Absent,
						"/compliance":                           collectortest.Absent,
						"/metric_coverage/protection.antimalware_healthy_pct": map[string]any{
							"passing_device_count": 2, "failing_device_count": 3, "unknown_device_count": 0, "not_applicable_device_count": 0,
						},
						"/devices/0/last_seen_at":                         "2026-06-30T09:15:00Z",
						"/devices/1/controls/antimalware_healthy/state":   "fail",
						"/devices/1/protection_modules/0":                 map[string]any{"kind": "antimalware", "enabled": true, "healthy": false},
						"/devices/3/management_state":                     "unmanaged",
						"/devices/3/controls/antimalware_installed/state": "fail",
						"/devices/3/protection_modules":                   []string{},
						"/devices/4/hostname":                             "erin-laptop",
						"/devices/4/controls/antimalware_installed/state": "pass",
						"/devices/4/controls/antimalware_healthy/state":   "fail",
					},
				},
			},
			{
				Name:          "API key rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{
					{Operation: opSignIn, Method: http.MethodPost, URL: kitBase + "/v1.0/jsonrpc/general", Status: http.StatusUnauthorized, Body: kitRejectedKey},
				},
			},
			{
				Name:          "API key rejected in a 200 response",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{
					{Operation: opSignIn, Method: http.MethodPost, URL: kitBase + "/v1.0/jsonrpc/general", Body: kitRejectedKey},
				},
			},
			{
				Name:      "empty company",
				Responses: kitResponses(kitEmptyTenant()),
				Expect: map[string]map[string]any{
					artifactPath: {
						"/scope/total_managed_computers":    0,
						"/compliance/compliance_percentage": nil,
						"/compliance/compliant_count":       0,
						"/endpoints/per_endpoint":           []string{},
						"/quarantine/per_computer":          []string{},
					},
					normalizedPath: {
						"/scope/discovery_complete":             true,
						"/scope/observed_device_count":          0,
						"/fleet/devices_present":                false,
						"/fleet/device_count":                   0,
						"/fleet/managed_device_count":           0,
						"/fleet/devices_by_os":                  collectortest.Absent,
						"/protection/antimalware_installed_pct": nil,
						"/protection/antimalware_healthy_pct":   nil,
						"/protection/edr_installed_pct":         nil,
						"/devices":                              []string{},
					},
				},
			},
			{
				// getEndpointsList lists nothing, and every endpoint is in
				// the Active Directory folder.
				Name:      "computers only in the Active Directory folder",
				Responses: kitResponses(kitActiveDirectoryOnlyTenant()),
				Expect: map[string]map[string]any{
					artifactPath: {
						"/scope/total_managed_computers":    5,
						"/compliance/compliance_percentage": 60,
					},
					normalizedPath: {
						"/scope/observed_device_count":          8,
						"/fleet/device_count":                   5,
						"/protection/antimalware_installed_pct": 80,
						"/devices/4/hostname":                   "erin-laptop",
					},
				},
			},
			{
				// The name search finds only a custom group whose name starts
				// with the folder's name, so no folder is listed.
				Name:      "no Active Directory folder",
				Responses: answering(clean, opInventory, kitADSearch, noFolder),
				Expect: map[string]map[string]any{
					artifactPath: {
						"/scope/total_managed_computers": 4,
						"/compliance/compliant_count":    2,
					},
					normalizedPath: {
						"/scope/observed_device_count":          6,
						"/fleet/device_count":                   4,
						"/protection/antimalware_installed_pct": 75,
						"/protection/antimalware_healthy_pct":   50,
					},
				},
			},
			{
				// The key cannot search the network inventory. The counts
				// that need the Active Directory folder are left out, and the
				// rows getEndpointsList gave stay. Whether every computer
				// was read is unknown.
				Name:      "Active Directory folder search denied",
				Responses: answering(clean, opInventory, kitADSearch, kitMissingNetworkAPI),
				Expect: map[string]map[string]any{
					artifactPath: {
						"/scope/total_managed_computers":    nil,
						"/compliance/compliance_percentage": nil,
						"/endpoints/per_endpoint/0/name":    "alice-laptop",
						"/policies/per_endpoint/0/computer": "alice-laptop",
					},
					normalizedPath: {
						"/scope/discovery_complete":    nil,
						"/scope/observed_device_count": collectortest.Absent,
						"/fleet":                       collectortest.Absent,
						"/protection":                  collectortest.Absent,
						"/devices/0/hostname":          "alice-laptop",
					},
				},
			},
			{
				// The key lacks the Network API for the detail calls. The
				// fleet counts stay, and the percentages that need the
				// details are left out.
				Name:      "every detail call denied",
				Responses: answering(clean, opDetails, "", kitMissingNetworkAPI),
				Expect: map[string]map[string]any{
					artifactPath: {
						"/scope/total_managed_computers":           5,
						"/policies/per_endpoint/0/modules_enabled": nil,
						"/policies/per_endpoint/3/modules_enabled": []string{},
					},
					normalizedPath: {
						"/fleet/device_count":           5,
						"/protection":                   collectortest.Absent,
						"/metric_coverage":              collectortest.Absent,
						"/devices/0/controls":           collectortest.Absent,
						"/devices/3/protection_modules": []string{},
					},
				},
			},
			{
				// GravityZone leaves bob-laptop's productOutdated out of its
				// row and carol-laptop's license and signature state out of
				// her details.
				Name:      "agent state not reported",
				Responses: kitResponses(kitTenantWithoutAgentState()),
				Expect: map[string]map[string]any{
					artifactPath: {
						"/scope/total_managed_computers":      5,
						"/compliance/compliance_percentage":   nil,
						"/compliance/compliant_count":         nil,
						"/endpoints/per_endpoint/1/compliant": nil,
					},
					normalizedPath: {
						"/protection/antimalware_healthy_pct":                                      25,
						"/metric_coverage/protection.antimalware_healthy_pct/unknown_device_count": 1,
						"/devices/2/controls/antimalware_healthy/state":                            "unknown",
						"/devices/2/protection_modules/0/healthy":                                  collectortest.Absent,
					},
				},
			},
			{
				// The counts cover every computer while the rows stop at the
				// cap, so the rollup checks must not recompute them.
				Name:      "more computers than the rows hold",
				Config:    map[string]any{"level": "audit"},
				Responses: kitResponses(kitFleetOverTheRowCap()),
				Expect: map[string]map[string]any{
					artifactPath: {
						"/scope/total_managed_computers":  EndpointsCap + 1,
						"/compliance/non_compliant_count": 2001,
						"/endpoints/truncated":            true,
						"/endpoints/truncated_dropped":    1,
					},
					normalizedPath: {
						"/fleet/device_count":                   EndpointsCap + 1,
						"/protection/antimalware_installed_pct": 100,
					},
				},
			},
			{
				// Reading stops at the collector's cap on endpoints. Every
				// value that needs the list is left out with a too_large gap.
				Name:      "endpoint list past the read cap",
				Config:    map[string]any{"level": "audit"},
				Responses: kitResponses(kitFleetOverTheReadCap()),
				Expect: map[string]map[string]any{
					artifactPath: {
						"/scope/total_managed_computers":    nil,
						"/compliance/compliance_percentage": nil,
						"/compliance/compliant_count":       nil,
						"/endpoints":                        collectortest.Absent,
					},
					normalizedPath: {
						"/scope/discovery_complete": false,
						"/fleet":                    collectortest.Absent,
						"/protection":               collectortest.Absent,
						"/devices":                  collectortest.Absent,
					},
				},
			},
			{
				Name:      "quarantine list past the read cap",
				Responses: kitResponses(kitQuarantineOverTheReadCap()),
				Expect: map[string]map[string]any{artifactPath: {
					"/scope/total_managed_computers": 5,
					"/quarantine":                    collectortest.Absent,
				}},
			},
			{
				// The collect key leaves the detailed file out, so the run
				// skips the quarantine list.
				Name:      "detailed file not collected",
				Config:    map[string]any{"collect": []any{"endpoint-posture"}},
				Responses: clean,
				Expect: map[string]map[string]any{normalizedPath: {
					"/fleet/device_count":                   5,
					"/protection/antimalware_installed_pct": 80,
				}},
			},
			{
				// The collect key leaves the endpoint-posture file out, so a
				// trust run skips the detail calls.
				Name:      "endpoint-posture file not collected",
				Config:    map[string]any{"collect": []any{"details"}, "level": "trust"},
				Responses: clean,
				Expect: map[string]map[string]any{artifactPath: {
					"/scope/total_managed_computers":    5,
					"/compliance/compliance_percentage": 60,
				}},
			},
		},
		Required: []string{opSignIn},
		// The diagnostics and the availability list repeat the gaps in text.
		Ignore: map[string][]string{
			artifactPath:   {"/diagnostics"},
			normalizedPath: {"/availability"},
		},
		Operations: []string{opSignIn, opEndpoints, opInventory, opDetails, opQuarantine},
		Faults:     gravityZoneFaults(),
	})
}
