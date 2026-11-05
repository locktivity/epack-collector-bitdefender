package collector

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"

	"github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

const (
	kitBase   = "https://cloud.gravityzone.bitdefender.com/api"
	kitAPIKey = "kit-gravityzone-api-key-0123456789"
)

// The operations the collector names, one per JSON-RPC method.
var (
	opSignIn     = bitdefender.OperationName("general", "getApiKeyDetails")
	opEndpoints  = bitdefender.OperationName("network", "getEndpointsList")
	opInventory  = bitdefender.OperationName("network", "getNetworkInventoryItems")
	opDetails    = bitdefender.OperationName("network", "getManagedEndpointDetails")
	opQuarantine = bitdefender.OperationName("quarantine/computers", "getQuarantineItemsList")
)

// kitADFolder is the ID of the clean company's Active Directory folder.
const kitADFolder = "64a1bc2e8f3d4a001e5c7890"

// kitTenant is a GravityZone company as the kit's canned responses describe
// it.
type kitTenant struct {
	enabledAPIs   []string
	endpointPages [][]bitdefender.Endpoint
	// adMatches answers the search for the Active Directory folder by name,
	// and adPages lists each folder's items, page by page, by folder ID.
	adMatches []map[string]any
	adPages   map[string][][]map[string]any
	// details answers getManagedEndpointDetails for each managed computer,
	// by endpoint ID. anyDetail, when set, answers every call instead.
	details         map[string]bitdefender.EndpointDetail
	anyDetail       *bitdefender.EndpointDetail
	quarantinePages [][]bitdefender.QuarantineItem
}

// adFolderItem is the Active Directory folder as getNetworkInventoryItems
// lists it, a group under the company's root container.
func adFolderItem(id string) map[string]any {
	return map[string]any{"id": id, "name": bitdefender.ActiveDirectoryFolder, "type": 4, "parentId": "6221f9592dab425234613c88", "companyId": "6221f9582dab425234613c82"}
}

// inventoryEndpoint is an endpoint as getNetworkInventoryItems lists it,
// with the getEndpointsList fields in details.
func inventoryEndpoint(e bitdefender.Endpoint) map[string]any {
	itemType := map[int]int{1: 5, 2: 6, 3: 7}[e.MachineType]
	if itemType == 0 {
		itemType = 5
	}
	details := map[string]any{"machineType": e.MachineType, "operatingSystemVersion": e.OperatingSystemVersion}
	if e.IsManaged != nil {
		details["isManaged"] = *e.IsManaged
	}
	if e.Policy != nil {
		details["policy"] = e.Policy
	}
	if e.ProductOutdated != nil {
		details["productOutdated"] = *e.ProductOutdated
	}
	return map[string]any{"id": e.ID, "name": e.Name, "type": itemType, "parentId": kitADFolder, "companyId": "6221f9582dab425234613c82", "details": details}
}

// kitCleanTenant is richMock's company over two pages of endpoints, with an
// unmanaged desktop and an EC2 instance on the second page, and an Active
// Directory folder over two pages. The folder holds a laptop with an
// expired license that only it lists, alice-laptop again, an organizational
// unit, and a device of machine type 0. Bob's signatures are out of date.
// Four managed computers, each with modules of its own, give the
// per-endpoint detail calls a first, a middle, and a last call. A fourth
// quarantined item is on the laptop only the folder lists.
func kitCleanTenant() kitTenant {
	m := richMock()
	dave := bitdefender.Endpoint{
		ID:                     "ep-5",
		Name:                   "dave-desktop",
		MachineType:            bitdefender.MachineTypeComputer,
		IsManaged:              boolPtr(false),
		OperatingSystemVersion: "Windows 10 Pro",
	}
	ec2 := managedComputer("ep-7", "ip-10-0-1-12", "Amazon Linux 2023", bitdefender.EndpointPolicy{ID: "pol-1", Name: "Default Policy", Applied: boolPtr(true)}, false)
	ec2.MachineType = 3
	erin := managedComputer("ep-6", "erin-laptop", "Windows 11 Enterprise", bitdefender.EndpointPolicy{ID: "pol-2", Name: "Engineering Policy", Applied: boolPtr(true)}, false)
	printer := bitdefender.Endpoint{ID: "ep-8", Name: "lobby-printer", IsManaged: boolPtr(false)}
	ou := map[string]any{"id": "ou-sales", "name": "Sales", "type": 4, "parentId": kitADFolder, "companyId": "6221f9582dab425234613c82"}

	aliceItem := bitdefender.QuarantineItem{
		ID:            "q-3",
		EndpointID:    "ep-1",
		ThreatName:    "EICAR-Test-File (not a virus)",
		ActionStatus:  intPtr(0),
		QuarantinedOn: "2026-06-20T08:30:00",
		Details:       &bitdefender.QuarantineDetails{FilePath: `C:\Users\alice\Downloads\eicar.com`},
	}
	erinItem := bitdefender.QuarantineItem{
		ID:            "q-4",
		EndpointID:    "ep-6",
		ThreatName:    "Gen:Variant.Test.3",
		ActionStatus:  intPtr(1),
		QuarantinedOn: "2026-06-25T16:10:00",
	}
	details := map[string]bitdefender.EndpointDetail{}
	for id, detail := range m.details {
		details[id] = *detail
	}
	bobDetail := details["ep-2"]
	bobDetail.Agent = &bitdefender.EndpointAgent{Licensed: intPtr(bitdefender.LicenseActive), SignatureOutdated: boolPtr(true), ProductOutdated: boolPtr(true)}
	details["ep-2"] = bobDetail
	erinDetail := *healthyDetail("2026-06-30T11:20:00", map[string]bool{"antimalware": true, "edrSensor": true, "firewall": true})
	erinDetail.Agent.Licensed = intPtr(2)
	details["ep-6"] = erinDetail

	return kitTenant{
		enabledAPIs:   []string{"network", "quarantine"},
		endpointPages: [][]bitdefender.Endpoint{m.endpoints[:3], {m.endpoints[3], dave, ec2}},
		adMatches: []map[string]any{
			adFolderItem(kitADFolder),
			// The name filter matches by prefix, so a custom group whose
			// name starts with the folder's name comes back too.
			{"id": "grp-ad-servers", "name": "Active Directory Servers", "type": 4, "parentId": "6221f9592dab425234613c80", "companyId": "6221f9582dab425234613c82"},
		},
		adPages: map[string][][]map[string]any{kitADFolder: {
			{ou, inventoryEndpoint(erin)},
			{inventoryEndpoint(m.endpoints[0]), inventoryEndpoint(printer)},
		}},
		details:         details,
		quarantinePages: [][]bitdefender.QuarantineItem{m.quarantine, {aliceItem, erinItem}},
	}
}

// kitEmptyTenant is a company with no endpoints, no Active Directory
// folder, and nothing quarantined.
func kitEmptyTenant() kitTenant {
	return kitTenant{
		enabledAPIs:     []string{"network", "quarantine"},
		endpointPages:   [][]bitdefender.Endpoint{{}},
		quarantinePages: [][]bitdefender.QuarantineItem{{}},
	}
}

// kitActiveDirectoryOnlyTenant is a company whose computers are all in the
// Active Directory folder, which getEndpointsList leaves out.
func kitActiveDirectoryOnlyTenant() kitTenant {
	t := kitCleanTenant()
	var page []map[string]any
	for _, e := range slices.Concat(t.endpointPages...) {
		page = append(page, inventoryEndpoint(e))
	}
	t.endpointPages = [][]bitdefender.Endpoint{{}}
	t.adPages[kitADFolder] = append([][]map[string]any{page}, t.adPages[kitADFolder]...)
	t.quarantinePages = [][]bitdefender.QuarantineItem{{}}
	return t
}

// kitTenantWithoutAgentState is the clean company with GravityZone leaving
// productOutdated out of bob-laptop's row, and the license and signature
// state out of carol-laptop's details.
func kitTenantWithoutAgentState() kitTenant {
	t := kitCleanTenant()
	bob := t.endpointPages[0][1]
	bob.ProductOutdated = nil
	t.endpointPages[0] = []bitdefender.Endpoint{t.endpointPages[0][0], bob, t.endpointPages[0][2]}
	carol := t.details["ep-3"]
	carol.Agent = nil
	t.details["ep-3"] = carol
	return t
}

// kitFleetOverTheRowCap is a company with one computer more than
// endpoints.per_endpoint holds, every tenth one with an outdated agent.
func kitFleetOverTheRowCap() kitTenant {
	policy := bitdefender.EndpointPolicy{ID: "pol-1", Name: "Default Policy", Applied: boolPtr(true)}
	computers := make([]bitdefender.Endpoint, EndpointsCap+1)
	for i := range computers {
		computers[i] = managedComputer(fmt.Sprintf("ep-%05d", i), fmt.Sprintf("host-%05d", i), "Windows 11 Pro", policy, i%10 == 0)
	}
	var pages [][]bitdefender.Endpoint
	for chunk := range slices.Chunk(computers, 100) {
		pages = append(pages, chunk)
	}
	return kitTenant{
		enabledAPIs:   []string{"network"},
		endpointPages: pages,
		anyDetail:     healthyDetail("2026-06-30T09:00:00", map[string]bool{"antimalware": true, "edrSensor": true}),
	}
}

// kitFleetOverTheReadCap is a company with a page of computers more than
// bitdefender.EndpointFetchCap.
func kitFleetOverTheReadCap() kitTenant {
	policy := bitdefender.EndpointPolicy{ID: "pol-1", Name: "Default Policy", Applied: boolPtr(true)}
	computers := make([]bitdefender.Endpoint, bitdefender.EndpointFetchCap+100)
	for i := range computers {
		computers[i] = managedComputer(fmt.Sprintf("ep-%05d", i), fmt.Sprintf("host-%05d", i), "Windows 11 Pro", policy, false)
	}
	var pages [][]bitdefender.Endpoint
	for chunk := range slices.Chunk(computers, 100) {
		pages = append(pages, chunk)
	}
	return kitTenant{enabledAPIs: []string{"network"}, endpointPages: pages}
}

// kitQuarantineOverTheReadCap is the clean company with a page of
// quarantined items more than bitdefender.QuarantineFetchCap.
func kitQuarantineOverTheReadCap() kitTenant {
	t := kitCleanTenant()
	items := make([]bitdefender.QuarantineItem, bitdefender.QuarantineFetchCap+100)
	for i := range items {
		items[i] = bitdefender.QuarantineItem{
			ID:            fmt.Sprintf("q-%05d", i),
			EndpointID:    "ep-1",
			ThreatName:    "EICAR-Test-File (not a virus)",
			ActionStatus:  intPtr(0),
			QuarantinedOn: "2026-06-20T08:30:00",
		}
	}
	t.quarantinePages = nil
	for chunk := range slices.Chunk(items, 100) {
		t.quarantinePages = append(t.quarantinePages, chunk)
	}
	return t
}

// kitResponses answers every call a clean internal-level run makes against
// tenant, in GravityZone's JSON-RPC form. Each page and each computer's
// details answer only the request whose params ask for them.
func kitResponses(t kitTenant) []collectortest.Response {
	responses := []collectortest.Response{
		kitResponse(opSignIn, kitBase+"/v1.0/jsonrpc/general", nil, kitResult(map[string]any{"enabledApis": t.enabledAPIs, "createdAt": "2025-11-03T09:12:44"})),
	}
	total := 0
	for _, page := range t.endpointPages {
		total += len(page)
	}
	for i, page := range t.endpointPages {
		result := map[string]any{"page": i + 1, "perPage": 100, "hasMoreRecords": i < len(t.endpointPages)-1, "items": nonNil(page)}
		if i == 0 {
			result["total"], result["pagesCount"] = total, len(t.endpointPages)
		}
		responses = append(responses, kitResponse(opEndpoints, kitBase+"/v1.1/jsonrpc/network", map[string]any{"page": i + 1}, kitResult(result)))
	}
	responses = append(responses, kitResponse(opInventory, kitBase+"/v1.1/jsonrpc/network",
		map[string]any{"filters": map[string]any{"details": map[string]any{"name": bitdefender.ActiveDirectoryFolder}}, "page": 1},
		kitResult(inventoryPage(nonNil(t.adMatches), 1, 1, len(t.adMatches)))))
	for _, folder := range slices.Sorted(maps.Keys(t.adPages)) {
		pages := t.adPages[folder]
		total := 0
		for _, page := range pages {
			total += len(page)
		}
		for i, page := range pages {
			responses = append(responses, kitResponse(opInventory, kitBase+"/v1.1/jsonrpc/network",
				map[string]any{"parentId": folder, "page": i + 1},
				kitResult(inventoryPage(nonNil(page), i+1, len(pages), total))))
		}
	}
	if t.anyDetail != nil {
		responses = append(responses, kitResponse(opDetails, kitBase+"/v1.0/jsonrpc/network", nil, kitResult(t.anyDetail)))
	}
	for _, id := range slices.Sorted(maps.Keys(t.details)) {
		responses = append(responses, kitResponse(opDetails, kitBase+"/v1.0/jsonrpc/network", map[string]any{"endpointId": id}, kitResult(t.details[id])))
	}
	total = 0
	for _, page := range t.quarantinePages {
		total += len(page)
	}
	pagesCount := len(t.quarantinePages)
	if total == 0 {
		pagesCount = 0
	}
	for i, page := range t.quarantinePages {
		result := map[string]any{"page": i + 1, "perPage": 100, "pagesCount": pagesCount, "total": total, "items": nonNil(page)}
		responses = append(responses, kitResponse(opQuarantine, kitBase+"/v1.0/jsonrpc/quarantine/computers", map[string]any{"page": i + 1}, kitResult(result)))
	}
	return responses
}

// inventoryPage is one page of getNetworkInventoryItems, version 1.1, which
// gives pagesCount and total on the first page only.
func inventoryPage(items []map[string]any, page, pages, total int) map[string]any {
	result := map[string]any{"page": page, "perPage": 100, "hasMoreRecords": page < pages, "items": items}
	if page == 1 {
		result["total"], result["pagesCount"] = total, pages
	}
	return result
}

// kitResponse answers the calls of op whose JSON-RPC params hold params, or
// every call of op when params is nil.
func kitResponse(op, url string, params map[string]any, body string) collectortest.Response {
	r := collectortest.Response{Operation: op, Method: http.MethodPost, URL: url, Body: body}
	if params != nil {
		r.RequestBody = kitJSON(map[string]any{"params": params})
	}
	return r
}

func kitResult(result any) string {
	return kitJSON(map[string]any{"id": "1", "jsonrpc": "2.0", "result": result})
}

// gzError is a JSON-RPC error in GravityZone's form, with the full
// description in data.details.
func gzError(code int, message, details string) string {
	return kitJSON(map[string]any{"id": "1", "jsonrpc": "2.0", "error": map[string]any{
		"code": code, "message": message, "data": map[string]any{"details": details},
	}})
}

func nonNil[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

func kitJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("kit fixture: %v", err))
	}
	return string(raw)
}

func intPtr(i int) *int { return &i }
