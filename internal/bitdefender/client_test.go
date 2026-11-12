package bitdefender

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

// rpcCall is one JSON-RPC request a test server received.
type rpcCall struct {
	Path   string
	Auth   string
	Method string
	Params map[string]any
}

// testServer answers each request with handle's status and body, and
// records the requests.
func testServer(t *testing.T, handle func(call rpcCall) (int, any)) (*Client, *[]rpcCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []rpcCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("request body: %v", err)
		}
		call := rpcCall{Path: r.URL.Path, Auth: r.Header.Get("Authorization"), Method: req.Method, Params: req.Params}
		mu.Lock()
		calls = append(calls, call)
		mu.Unlock()
		status, body := handle(call)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if s, ok := body.(string); ok {
			_, _ = w.Write([]byte(s))
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return New(srv.Client(), srv.URL+"/api/", "test-api-key"), &calls
}

func result(v any) map[string]any {
	return map[string]any{"id": "1", "jsonrpc": "2.0", "result": v}
}

func rpcFailure(code int, message, details string) map[string]any {
	return map[string]any{"id": "1", "jsonrpc": "2.0", "error": map[string]any{
		"code": code, "message": message, "data": map[string]any{"details": details},
	}}
}

func TestSignInSendsTheKeyAsBasicAuth(t *testing.T) {
	c, calls := testServer(t, func(rpcCall) (int, any) {
		return http.StatusOK, result(map[string]any{"enabledApis": []string{"network", "quarantine"}, "createdAt": "2026-01-01T00:00:00"})
	})
	details, err := c.GetAPIKeyDetails(context.Background())
	if err != nil {
		t.Fatalf("GetAPIKeyDetails: %v", err)
	}
	if len(details.EnabledAPIs) != 2 || details.EnabledAPIs[0] != "network" {
		t.Errorf("enabled APIs = %v", details.EnabledAPIs)
	}
	got := (*calls)[0]
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("test-api-key:"))
	if got.Path != "/api/v1.0/jsonrpc/general" || got.Method != "getApiKeyDetails" || got.Auth != wantAuth {
		t.Errorf("request = %+v, want getApiKeyDetails on /api/v1.0/jsonrpc/general with %q", got, wantAuth)
	}
}

func TestListEndpointsAsksForWhatComplianceNeeds(t *testing.T) {
	c, calls := testServer(t, func(call rpcCall) (int, any) {
		if call.Params["page"] == float64(1) {
			return http.StatusOK, result(map[string]any{"hasMoreRecords": true, "items": []map[string]any{{"id": "ep-1", "isManaged": true, "productOutdated": true}}})
		}
		return http.StatusOK, result(map[string]any{"hasMoreRecords": false, "items": []map[string]any{{"id": "ep-2"}}})
	})
	endpoints, err := c.ListEndpoints(context.Background(), "group-1", true)
	if err != nil {
		t.Fatalf("ListEndpoints: %v", err)
	}
	if len(endpoints) != 2 || endpoints[0].ProductOutdated == nil || !*endpoints[0].ProductOutdated || endpoints[1].IsManaged != nil {
		t.Fatalf("endpoints = %+v, want both pages with unreported flags left nil", endpoints)
	}
	if len(*calls) != 2 {
		t.Fatalf("calls = %d, want one per page", len(*calls))
	}
	first := (*calls)[0]
	if first.Path != "/api/v1.1/jsonrpc/network" || first.Method != "getEndpointsList" {
		t.Errorf("request = %+v, want getEndpointsList on version 1.1", first)
	}
	want := map[string]any{
		"parentId": "group-1",
		"page":     float64(1),
		"perPage":  float64(100),
		"filters":  map[string]any{"depth": map[string]any{"allItemsRecursively": true}},
		"options":  map[string]any{"returnProductOutdated": true, "includeScanLogs": true},
	}
	if b1, b2 := mustJSON(t, first.Params), mustJSON(t, want); b1 != b2 {
		t.Errorf("params = %s, want %s", b1, b2)
	}
}

func TestFindActiveDirectoryFoldersKeepsTheExactName(t *testing.T) {
	c, calls := testServer(t, func(rpcCall) (int, any) {
		return http.StatusOK, result(map[string]any{"hasMoreRecords": false, "items": []map[string]any{
			{"id": "ad-1", "name": "Active Directory", "type": 4},
			{"id": "grp-2", "name": "Active Directory Servers", "type": 4},
			{"id": "ep-3", "name": "Active Directory", "type": 5, "details": map[string]any{"machineType": 1}},
		}})
	})
	ids, err := c.FindActiveDirectoryFolders(context.Background())
	if err != nil {
		t.Fatalf("FindActiveDirectoryFolders: %v", err)
	}
	if len(ids) != 1 || ids[0] != "ad-1" {
		t.Errorf("folders = %v, want only ad-1", ids)
	}
	first := (*calls)[0]
	want := map[string]any{"page": float64(1), "perPage": float64(100), "filters": map[string]any{"details": map[string]any{"name": "Active Directory"}}}
	if first.Path != "/api/v1.1/jsonrpc/network" || first.Method != "getNetworkInventoryItems" || mustJSON(t, first.Params) != mustJSON(t, want) {
		t.Errorf("request = %+v, want getNetworkInventoryItems on version 1.1 with %s", first, mustJSON(t, want))
	}
}

func TestListInventoryEndpointsReadsEndpointsBelowTheFolder(t *testing.T) {
	c, calls := testServer(t, func(call rpcCall) (int, any) {
		if call.Params["page"] == float64(1) {
			return http.StatusOK, result(map[string]any{"hasMoreRecords": true, "items": []map[string]any{
				{"id": "ou-1", "name": "Sales", "type": 4},
				{"id": "ep-1", "name": "erin-laptop", "type": 5, "details": map[string]any{
					"isManaged": true, "machineType": 1, "operatingSystemVersion": "Windows 11 Enterprise",
					"policy": map[string]any{"id": "pol-1", "name": "Default Policy", "applied": true}, "productOutdated": false,
				}},
			}})
		}
		return http.StatusOK, result(map[string]any{"hasMoreRecords": false, "items": []map[string]any{
			{"id": "ep-2", "name": "build-vm", "type": 6, "details": map[string]any{"machineType": 2}},
		}})
	})
	endpoints, err := c.ListInventoryEndpoints(context.Background(), "ad-1", true)
	if err != nil {
		t.Fatalf("ListInventoryEndpoints: %v", err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("endpoints = %+v, want the two endpoints without the unit", endpoints)
	}
	erin := endpoints[0]
	if erin.ID != "ep-1" || erin.MachineType != MachineTypeComputer || erin.IsManaged == nil || !*erin.IsManaged ||
		erin.Policy == nil || erin.Policy.Applied == nil || !*erin.Policy.Applied || erin.ProductOutdated == nil || *erin.ProductOutdated {
		t.Errorf("erin-laptop = %+v, want the details fields", erin)
	}
	if endpoints[1].MachineType != 2 || endpoints[1].IsManaged != nil {
		t.Errorf("build-vm = %+v, want machineType 2 with isManaged unreported", endpoints[1])
	}
	want := map[string]any{
		"parentId": "ad-1",
		"page":     float64(1),
		"perPage":  float64(100),
		"filters":  map[string]any{"depth": map[string]any{"allItemsRecursively": true}},
		"options":  map[string]any{"endpoints": map[string]any{"returnProductOutdated": true, "includeScanLogs": true}},
	}
	if got := mustJSON(t, (*calls)[0].Params); got != mustJSON(t, want) {
		t.Errorf("params = %s, want %s", got, mustJSON(t, want))
	}
	if len(*calls) != 2 {
		t.Errorf("calls = %d, want one per page", len(*calls))
	}
}

func TestInventoryEndpointWithoutMachineTypeIsInvalid(t *testing.T) {
	c, _ := testServer(t, func(rpcCall) (int, any) {
		return http.StatusOK, result(map[string]any{"hasMoreRecords": false, "items": []map[string]any{{"id": "ep-1", "name": "erin-laptop", "type": 5}}})
	})
	_, err := c.ListInventoryEndpoints(context.Background(), "ad-1", false)
	if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
		t.Errorf("code = %s, want invalid_response (error %v)", got, err)
	}
}

// A version 1.1 page without hasMoreRecords does not say whether the list
// goes on, so the read fails rather than stop at that page.
func TestPageWithoutHasMoreRecordsIsInvalid(t *testing.T) {
	reads := map[string]func(*Client) error{
		"getEndpointsList": func(c *Client) error {
			_, err := c.ListEndpoints(context.Background(), "", false)
			return err
		},
		"getNetworkInventoryItems folder search": func(c *Client) error {
			_, err := c.FindActiveDirectoryFolders(context.Background())
			return err
		},
		"getNetworkInventoryItems folder list": func(c *Client) error {
			_, err := c.ListInventoryEndpoints(context.Background(), "ad-1", false)
			return err
		},
	}
	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			c, calls := testServer(t, func(rpcCall) (int, any) {
				return http.StatusOK, result(map[string]any{"page": 1, "perPage": 100, "total": 2, "pagesCount": 2, "items": []map[string]any{
					{"id": "ep-1", "name": "Active Directory", "type": 4, "machineType": 1},
				}})
			})
			err := read(c)
			if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
				t.Errorf("code = %s, want invalid_response (error %v)", got, err)
			}
			if len(*calls) != 1 {
				t.Errorf("calls = %d, want 1", len(*calls))
			}
		})
	}
}

func TestDetailsReadTheAgentAndLastSeen(t *testing.T) {
	c, _ := testServer(t, func(rpcCall) (int, any) {
		return http.StatusOK, result(map[string]any{
			"lastSeen": "2026-08-22T13:46:59",
			"agent":    map[string]any{"licensed": 2, "signatureOutdated": true, "productOutdated": false},
			"modules":  map[string]any{"antimalware": true, "edrSensor": false, "firewall": nil},
		})
	})
	d, err := c.GetManagedEndpointDetails(context.Background(), "ep-1")
	if err != nil {
		t.Fatalf("GetManagedEndpointDetails: %v", err)
	}
	if d.LastSeen != "2026-08-22T13:46:59" || d.Agent == nil || *d.Agent.Licensed != 2 || !*d.Agent.SignatureOutdated || *d.Agent.ProductOutdated {
		t.Errorf("detail = %+v, agent %+v", d, d.Agent)
	}
	if !*d.Modules["antimalware"] || *d.Modules["edrSensor"] || d.Modules["firewall"] != nil {
		t.Errorf("modules = %v, want a null flag left nil", d.Modules)
	}
}

func TestListQuarantineItemsReadsEveryPage(t *testing.T) {
	c, calls := testServer(t, func(call rpcCall) (int, any) {
		item := map[string]any{"id": "q", "endpointId": "ep-1", "actionStatus": 1, "quarantinedOn": "2026-06-15T12:00:00"}
		return http.StatusOK, result(map[string]any{"pagesCount": 2, "total": 2, "items": []map[string]any{item}})
	})
	items, err := c.ListQuarantineItems(context.Background())
	if err != nil {
		t.Fatalf("ListQuarantineItems: %v", err)
	}
	if len(items) != 2 || len(*calls) != 2 || (*calls)[0].Path != "/api/v1.0/jsonrpc/quarantine/computers" {
		t.Fatalf("items = %d over %d calls to %s, want 2 over 2 calls to the computers service", len(items), len(*calls), (*calls)[0].Path)
	}
	if items[0].QuarantinedOn != "2026-06-15T12:00:00" || items[0].ActionStatus == nil || *items[0].ActionStatus != 1 {
		t.Errorf("item = %+v", items[0])
	}
}

func TestListsPastTheReadCapAreTooLarge(t *testing.T) {
	page := func(n int) []map[string]any {
		items := make([]map[string]any, n)
		for i := range items {
			items[i] = map[string]any{"id": "x", "endpointId": "ep-1", "machineType": MachineTypeComputer}
		}
		return items
	}
	t.Run("endpoints", func(t *testing.T) {
		c, calls := testServer(t, func(rpcCall) (int, any) {
			return http.StatusOK, result(map[string]any{"hasMoreRecords": true, "items": page(100)})
		})
		_, err := c.ListEndpoints(context.Background(), "", false)
		if code := componentsdk.Classify(err); code != componentsdk.CodeTooLarge {
			t.Fatalf("code = %q (%v), want too_large", code, err)
		}
		if len(*calls) != EndpointFetchCap/100 {
			t.Errorf("calls = %d, want %d", len(*calls), EndpointFetchCap/100)
		}
	})
	t.Run("quarantine", func(t *testing.T) {
		c, calls := testServer(t, func(rpcCall) (int, any) {
			return http.StatusOK, result(map[string]any{"pagesCount": QuarantineFetchCap/100 + 1, "items": page(100)})
		})
		_, err := c.ListQuarantineItems(context.Background())
		if code := componentsdk.Classify(err); code != componentsdk.CodeTooLarge {
			t.Fatalf("code = %q (%v), want too_large", code, err)
		}
		if len(*calls) != QuarantineFetchCap/100 {
			t.Errorf("calls = %d, want %d", len(*calls), QuarantineFetchCap/100)
		}
	})
}

func TestErrorsCarryGravityZoneCodes(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   any
		code   componentsdk.Code
		vendor string
	}{
		{"rejected key", http.StatusUnauthorized, rpcFailure(-32001, "Authorization error", "The API key is not valid"), componentsdk.CodeAuthFailed, "-32001"},
		{"API not enabled", http.StatusForbidden, rpcFailure(-32001, "Authorization error", "API Key is not allowed to access the selected API: Network"), componentsdk.CodePermissionDenied, "-32001"},
		{"throttled", http.StatusTooManyRequests, rpcFailure(-32003, "Too many requests", "Rate limit exceeded"), componentsdk.CodeRateLimited, "-32003"},
		{"vendor outage", http.StatusInternalServerError, "upstream failed", componentsdk.CodeVendorError, ""},
		{"authorization error in a 200", http.StatusOK, rpcFailure(-32001, "Authorization error", "API Key is not allowed to access the selected API: Network"), componentsdk.CodePermissionDenied, "-32001"},
		{"server error in a 200", http.StatusOK, rpcFailure(-32000, "Server error", "An unexpected error occurred"), componentsdk.CodeVendorError, "-32000"},
		{"invalid params in a 200", http.StatusOK, rpcFailure(-32602, "Invalid params", "Invalid parameter: perPage"), componentsdk.CodeInvalidResponse, "-32602"},
		{"not found in a 200", http.StatusOK, rpcFailure(-32002, "Resource not found", "There is no group with the specified ID"), componentsdk.CodeInvalidResponse, "-32002"},
		{"throttled in a 200", http.StatusOK, rpcFailure(-32003, "Too many requests", "Rate limit exceeded"), componentsdk.CodeRateLimited, "-32003"},
		{"malformed body", http.StatusOK, "{not json", componentsdk.CodeInvalidResponse, ""},
		{"no result", http.StatusOK, `{"id":"1","jsonrpc":"2.0"}`, componentsdk.CodeInvalidResponse, ""},
		{"null result", http.StatusOK, `{"id":"1","jsonrpc":"2.0","result":null}`, componentsdk.CodeInvalidResponse, ""},
		{"no items list", http.StatusOK, result(map[string]any{"hasMoreRecords": false}), componentsdk.CodeInvalidResponse, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testServer(t, func(rpcCall) (int, any) { return tc.status, tc.body })
			_, err := c.ListEndpoints(context.Background(), "", false)
			if got := componentsdk.Classify(err); got != tc.code {
				t.Errorf("code = %s, want %s (error %v)", got, tc.code, err)
			}
			if got := componentsdk.VendorCodeOf(err); got != tc.vendor {
				t.Errorf("vendor code = %q, want %q", got, tc.vendor)
			}
		})
	}
}

func TestClassifyResponseReadsErrorsInA200(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   any
		code   componentsdk.Code
		ok     bool
	}{
		{"throttled in a 200", http.StatusOK, rpcFailure(-32003, "Too many requests", "Rate limit exceeded"), componentsdk.CodeRateLimited, true},
		{"server error in a 200", http.StatusOK, rpcFailure(-32000, "Server error", "An unexpected error occurred"), componentsdk.CodeVendorError, true},
		{"authorization error in a 200", http.StatusOK, rpcFailure(-32001, "Authorization error", "API Key is not allowed to access the selected API: Network"), componentsdk.CodePermissionDenied, true},
		{"result", http.StatusOK, result(map[string]any{"items": []any{}}), "", false},
		{"malformed body", http.StatusOK, "{not json", "", false},
		{"throttled with a 429", http.StatusTooManyRequests, rpcFailure(-32003, "Too many requests", "Rate limit exceeded"), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, ok := tc.body.(string)
			if !ok {
				body = mustJSON(t, tc.body)
			}
			code, classified := ClassifyResponse(&http.Response{StatusCode: tc.status}, []byte(body))
			if code != tc.code || classified != tc.ok {
				t.Errorf("ClassifyResponse = %q, %v; want %q, %v", code, classified, tc.code, tc.ok)
			}
		})
	}
}

// getApiKeyDetails needs no API on the key, so an authorization error there
// means the key itself was rejected.
func TestSignInReadsAnAuthorizationErrorAsARejectedKey(t *testing.T) {
	c, _ := testServer(t, func(rpcCall) (int, any) {
		return http.StatusOK, rpcFailure(-32001, "Authorization error", "The API key is not valid")
	})
	_, err := c.GetAPIKeyDetails(context.Background())
	if got := componentsdk.Classify(err); got != componentsdk.CodeAuthFailed {
		t.Errorf("code = %s, want auth_failed (error %v)", got, err)
	}
}

func TestDetailsWithoutModulesAreInvalid(t *testing.T) {
	c, _ := testServer(t, func(rpcCall) (int, any) {
		return http.StatusOK, result(map[string]any{"malwareStatus": map[string]any{"detection": false}})
	})
	_, err := c.GetManagedEndpointDetails(context.Background(), "ep-1")
	if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
		t.Errorf("code = %s, want invalid_response (error %v)", got, err)
	}
}

func TestNamesAndHosts(t *testing.T) {
	if got := OperationName("quarantine/computers", "getQuarantineItemsList"); got != "bitdefender.quarantine.computers.getQuarantineItemsList" {
		t.Errorf("OperationName = %q", got)
	}
	if got := Host("https://CloudGZ.GravityZone.Bitdefender.com/api"); got != "cloudgz.gravityzone.bitdefender.com" {
		t.Errorf("Host = %q", got)
	}
	for service, want := range map[string]string{"network": "network", "quarantine/computers": "quarantine", "general": ""} {
		if got := Permission(service); got != want {
			t.Errorf("Permission(%q) = %q, want %q", service, got, want)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
