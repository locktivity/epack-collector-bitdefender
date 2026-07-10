package bitdefender

import "context"

// MachineTypeComputer is GravityZone's machineType value for a physical or
// virtual computer, as opposed to 2 (virtual machine under a hypervisor
// integration), 3 (EC2 instance), or 0 (other).
const MachineTypeComputer = 1

// EndpointPolicy is the policy assignment summary embedded in both
// getEndpointsList rows and getManagedEndpointDetails.
type EndpointPolicy struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Applied bool   `json:"applied"`
}

// EndpointLastScan is the most recent successful scan summary embedded in
// getEndpointsList rows.
type EndpointLastScan struct {
	Name string `json:"name"`
	Date string `json:"date"`
}

// Endpoint is one row from getEndpointsList (Network API, v1.1). Only the
// fields this collector uses are modeled; the full response carries more.
type Endpoint struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	FQDN                   string            `json:"fqdn"`
	GroupID                string            `json:"groupId"`
	IsManaged              bool              `json:"isManaged"`
	MachineType            int               `json:"machineType"`
	OperatingSystemVersion string            `json:"operatingSystemVersion"`
	ManagedWithBest        bool              `json:"managedWithBest"`
	Policy                 EndpointPolicy    `json:"policy"`
	ProductOutdated        bool              `json:"productOutdated"`
	LastSuccessfulScan     *EndpointLastScan `json:"lastSuccessfulScan"`
}

type endpointsListParams struct {
	ParentID string `json:"parentId,omitempty"`
	Page     int    `json:"page"`
	PerPage  int    `json:"perPage"`
}

type endpointsListResult struct {
	Total          int        `json:"total"`
	Page           int        `json:"page"`
	PagesCount     int        `json:"pagesCount"`
	HasMoreRecords bool       `json:"hasMoreRecords"`
	Items          []Endpoint `json:"items"`
}

// EndpointFetchCap bounds pagination defensively.
const EndpointFetchCap = 50000

// ListEndpoints returns every endpoint under parentID (the company's root
// group if parentID is empty), 100 per page. Requires the Network API.
func (c *Client) ListEndpoints(ctx context.Context, parentID string) ([]Endpoint, error) {
	var all []Endpoint
	page := 1
	for {
		var res endpointsListResult
		params := endpointsListParams{ParentID: parentID, Page: page, PerPage: 100}
		if err := c.call(ctx, "network", "getEndpointsList", params, &res); err != nil {
			return nil, err
		}
		all = append(all, res.Items...)
		if !res.HasMoreRecords || len(res.Items) == 0 || len(all) >= EndpointFetchCap {
			break
		}
		page++
	}
	if len(all) > EndpointFetchCap {
		all = all[:EndpointFetchCap]
	}
	return all, nil
}

// MalwareStatus reports whether malware was detected/remains on an
// endpoint in the last 24 hours.
type MalwareStatus struct {
	Detection bool `json:"detection"`
	Infected  bool `json:"infected"`
}

// EndpointDetail is the subset of getManagedEndpointDetails this collector
// uses: malware status, per-module enablement, and the policy assignment
// (repeated here with the same shape as the list response).
type EndpointDetail struct {
	MalwareStatus *MalwareStatus  `json:"malwareStatus"`
	Modules       map[string]bool `json:"modules"`
	Policy        EndpointPolicy  `json:"policy"`
}

type endpointDetailParams struct {
	EndpointID string `json:"endpointId"`
}

// GetManagedEndpointDetails fetches per-endpoint module/policy/malware
// detail. Requires the Network API.
func (c *Client) GetManagedEndpointDetails(ctx context.Context, endpointID string) (*EndpointDetail, error) {
	var out EndpointDetail
	params := endpointDetailParams{EndpointID: endpointID}
	if err := c.call(ctx, "network", "getManagedEndpointDetails", params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
