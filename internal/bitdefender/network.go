package bitdefender

import (
	"context"
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// MachineTypeComputer is GravityZone's machineType value for a physical or
// virtual computer, as opposed to 2 (virtual machine under a hypervisor
// integration), 3 (EC2 instance), or 0 (other).
const MachineTypeComputer = 1

// EndpointPolicy is the policy assignment summary embedded in
// getEndpointsList rows.
type EndpointPolicy struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Applied *bool  `json:"applied,omitempty"`
}

// EndpointLastScan is the most recent successful scan summary embedded in
// getEndpointsList rows.
type EndpointLastScan struct {
	Name string `json:"name"`
	Date string `json:"date"`
}

// Endpoint is one row from getEndpointsList (Network API, version 1.1).
// Only the fields this collector uses are modeled; the full response carries
// more. A flag GravityZone leaves out decodes as nil, never as false.
type Endpoint struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	IsManaged              *bool             `json:"isManaged,omitempty"`
	MachineType            int               `json:"machineType"`
	OperatingSystemVersion string            `json:"operatingSystemVersion,omitempty"`
	Policy                 *EndpointPolicy   `json:"policy,omitempty"`
	ProductOutdated        *bool             `json:"productOutdated,omitempty"`
	LastSuccessfulScan     *EndpointLastScan `json:"lastSuccessfulScan,omitempty"`
}

type endpointsListParams struct {
	ParentID string               `json:"parentId,omitempty"`
	Page     int                  `json:"page"`
	PerPage  int                  `json:"perPage"`
	Filters  endpointsListFilters `json:"filters"`
	Options  endpointsListOptions `json:"options"`
}

type endpointsListFilters struct {
	Depth depthFilter `json:"depth"`
}

type depthFilter struct {
	AllItemsRecursively bool `json:"allItemsRecursively"`
}

type endpointsListOptions struct {
	ReturnProductOutdated bool `json:"returnProductOutdated"`
	IncludeScanLogs       bool `json:"includeScanLogs"`
}

// pagedResult is one page of a version 1.1 list method, which reports
// hasMoreRecords on every page.
type pagedResult[T any] struct {
	HasMoreRecords *bool `json:"hasMoreRecords"`
	Items          *[]T  `json:"items"`
}

// EndpointFetchCap bounds how many items the collector reads from one list
// of endpoints.
const EndpointFetchCap = 50000

// readPages calls method on the Network API's version 1.1 page by page, from
// page 1, until GravityZone reports no more records. params builds each
// page's params. A page without hasMoreRecords fails the read, since it does
// not say whether more pages follow. A list longer than EndpointFetchCap
// fails the read rather than be counted in part. what names the list's items
// in that error.
func readPages[T any](ctx context.Context, c *Client, method, what string, params func(page int) any) ([]T, error) {
	all := []T{}
	for page := 1; ; page++ {
		var res pagedResult[T]
		if err := c.call(ctx, "v1.1", "network", method, params(page), &res); err != nil {
			return nil, err
		}
		if res.Items == nil {
			return nil, invalidResponse(method, "has no items list")
		}
		if res.HasMoreRecords == nil {
			return nil, invalidResponse(method, "has no hasMoreRecords")
		}
		all = append(all, *res.Items...)
		if !*res.HasMoreRecords || len(*res.Items) == 0 {
			return all, nil
		}
		if len(all) >= EndpointFetchCap {
			return nil, componentsdk.CodeError(componentsdk.CodeTooLarge,
				fmt.Errorf("GravityZone lists more than %d %s, more than the collector reads", EndpointFetchCap, what))
		}
	}
}

// ListEndpoints returns every endpoint under parentID and the groups below
// it (the API key's company when parentID is empty), 100 per page, with each
// endpoint's productOutdated flag and, when scanLogs is set, its last
// successful scan. It calls version 1.1 of getEndpointsList, the version
// that reports hasMoreRecords. A company with more endpoints than
// EndpointFetchCap fails the read rather than be counted in part.
// Bitdefender's docs say to read the endpoints in the Active Directory folder
// with getNetworkInventoryItems, which ListInventoryEndpoints calls. Requires
// the Network API.
func (c *Client) ListEndpoints(ctx context.Context, parentID string, scanLogs bool) ([]Endpoint, error) {
	return readPages[Endpoint](ctx, c, "getEndpointsList", "endpoints", func(page int) any {
		params := endpointsListParams{ParentID: parentID, Page: page, PerPage: 100}
		params.Filters.Depth.AllItemsRecursively = true
		params.Options = endpointsListOptions{ReturnProductOutdated: true, IncludeScanLogs: scanLogs}
		return params
	})
}

// Network inventory item types, from getNetworkInventoryItems. Types 5 to 7
// are endpoints and carry details.
const (
	inventoryRootContainer  = 2
	inventoryCompanyFolder  = 3
	inventoryGroup          = 4
	inventoryComputer       = 5
	inventoryVirtualMachine = 6
	inventoryEC2Instance    = 7
)

// ActiveDirectoryFolder is the name of the network inventory folder that
// holds the endpoints GravityZone syncs from Active Directory.
const ActiveDirectoryFolder = "Active Directory"

// InventoryItem is one row from getNetworkInventoryItems (Network API,
// version 1.1). Only the fields this collector uses are modeled.
type InventoryItem struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Type    int               `json:"type"`
	Details *InventoryDetails `json:"details,omitempty"`
}

// InventoryDetails is the details object of an endpoint item. Its fields
// match a getEndpointsList row. A flag GravityZone leaves out decodes as nil.
type InventoryDetails struct {
	IsManaged              *bool             `json:"isManaged,omitempty"`
	MachineType            *int              `json:"machineType,omitempty"`
	OperatingSystemVersion string            `json:"operatingSystemVersion,omitempty"`
	Policy                 *EndpointPolicy   `json:"policy,omitempty"`
	ProductOutdated        *bool             `json:"productOutdated,omitempty"`
	LastSuccessfulScan     *EndpointLastScan `json:"lastSuccessfulScan,omitempty"`
}

type inventoryParams struct {
	ParentID string            `json:"parentId,omitempty"`
	Page     int               `json:"page"`
	PerPage  int               `json:"perPage"`
	Filters  inventoryFilters  `json:"filters"`
	Options  *inventoryOptions `json:"options,omitempty"`
}

type inventoryFilters struct {
	Depth   *depthFilter   `json:"depth,omitempty"`
	Details *detailsFilter `json:"details,omitempty"`
}

type detailsFilter struct {
	Name string `json:"name"`
}

type inventoryOptions struct {
	Endpoints endpointsListOptions `json:"endpoints"`
}

// FindActiveDirectoryFolders returns the IDs of the network inventory
// folders named ActiveDirectoryFolder in the API key's company, as
// Bitdefender's getNetworkInventoryItems example finds the Active Directory
// folder. The name filter matches names that start with the text, so only
// folders and groups with exactly that name are kept. Requires the Network
// API.
func (c *Client) FindActiveDirectoryFolders(ctx context.Context) ([]string, error) {
	items, err := readPages[InventoryItem](ctx, c, "getNetworkInventoryItems", "inventory items", func(page int) any {
		return inventoryParams{Page: page, PerPage: 100, Filters: inventoryFilters{Details: &detailsFilter{Name: ActiveDirectoryFolder}}}
	})
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, item := range items {
		switch item.Type {
		case inventoryRootContainer, inventoryCompanyFolder, inventoryGroup:
			if item.Name == ActiveDirectoryFolder && item.ID != "" {
				ids = append(ids, item.ID)
			}
		}
	}
	return ids, nil
}

// ListInventoryEndpoints returns every endpoint getNetworkInventoryItems
// lists under parentID and the folders below it, 100 items per page, in the
// form getEndpointsList gives them. It asks for each endpoint's
// productOutdated flag and, when scanLogs is set, its last successful scan.
// Folders and other items that are not computers, virtual machines, or EC2
// instances are skipped. Requires the Network API.
func (c *Client) ListInventoryEndpoints(ctx context.Context, parentID string, scanLogs bool) ([]Endpoint, error) {
	const method = "getNetworkInventoryItems"
	items, err := readPages[InventoryItem](ctx, c, method, "inventory items", func(page int) any {
		return inventoryParams{
			ParentID: parentID, Page: page, PerPage: 100,
			Filters: inventoryFilters{Depth: &depthFilter{AllItemsRecursively: true}},
			Options: &inventoryOptions{Endpoints: endpointsListOptions{ReturnProductOutdated: true, IncludeScanLogs: scanLogs}},
		}
	})
	if err != nil {
		return nil, err
	}
	var out []Endpoint
	for _, item := range items {
		switch item.Type {
		case inventoryComputer, inventoryVirtualMachine, inventoryEC2Instance:
		default:
			continue
		}
		d := item.Details
		if d == nil || d.MachineType == nil {
			return nil, invalidResponse(method, "lists an endpoint with no machineType")
		}
		out = append(out, Endpoint{
			ID:                     item.ID,
			Name:                   item.Name,
			IsManaged:              d.IsManaged,
			MachineType:            *d.MachineType,
			OperatingSystemVersion: d.OperatingSystemVersion,
			Policy:                 d.Policy,
			ProductOutdated:        d.ProductOutdated,
			LastSuccessfulScan:     d.LastSuccessfulScan,
		})
	}
	return out, nil
}

// MalwareStatus reports whether malware was detected/remains on an
// endpoint in the last 24 hours.
type MalwareStatus struct {
	Detection bool `json:"detection"`
	Infected  bool `json:"infected"`
}

// LicenseActive is the agent.licensed value of an endpoint with an active
// license. GravityZone reports 0 for pending authentication, 2 for an expired
// license, and 6 for no license.
const LicenseActive = 1

// EndpointAgent is the agent state in getManagedEndpointDetails. A value
// GravityZone leaves out decodes as nil.
type EndpointAgent struct {
	Licensed          *int  `json:"licensed,omitempty"`
	SignatureOutdated *bool `json:"signatureOutdated,omitempty"`
	ProductOutdated   *bool `json:"productOutdated,omitempty"`
}

// EndpointDetail is the subset of getManagedEndpointDetails this collector
// uses: the last sync with Control Center, the agent's license and
// signature state, malware status, and per-module enablement. A module flag
// GravityZone leaves out or sends as null decodes as nil.
type EndpointDetail struct {
	LastSeen      string           `json:"lastSeen,omitempty"`
	Agent         *EndpointAgent   `json:"agent,omitempty"`
	MalwareStatus *MalwareStatus   `json:"malwareStatus,omitempty"`
	Modules       map[string]*bool `json:"modules"`
}

type endpointDetailParams struct {
	EndpointID string `json:"endpointId"`
}

// GetManagedEndpointDetails fetches a managed endpoint's agent, module, and
// malware detail. GravityZone answers it only for managed endpoints.
// Requires the Network API.
func (c *Client) GetManagedEndpointDetails(ctx context.Context, endpointID string) (*EndpointDetail, error) {
	const method = "getManagedEndpointDetails"
	var out EndpointDetail
	if err := c.call(ctx, "v1.0", "network", method, endpointDetailParams{EndpointID: endpointID}, &out); err != nil {
		return nil, err
	}
	if out.Modules == nil {
		return nil, invalidResponse(method, "has no modules")
	}
	return &out, nil
}
