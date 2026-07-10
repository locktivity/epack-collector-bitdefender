package bitdefender

import "context"

// QuarantineDetails is the "computers" service's details sub-object for a
// quarantined item. Only filePath is modeled; the full object also carries
// fields like file size, which this collector doesn't use.
type QuarantineDetails struct {
	FilePath string `json:"filePath"`
}

// QuarantineItem is one row from getQuarantineItemsList (Quarantine API,
// "computers" service).
type QuarantineItem struct {
	ID           string             `json:"id"`
	EndpointID   string             `json:"endpointId"`
	ThreatName   string             `json:"threatName"`
	ActionStatus int                `json:"actionStatus"`
	Date         string             `json:"date"`
	Details      *QuarantineDetails `json:"details"`
}

type quarantineListParams struct {
	Page    int `json:"page"`
	PerPage int `json:"perPage"`
}

type quarantineListResult struct {
	Total          int              `json:"total"`
	HasMoreRecords bool             `json:"hasMoreRecords"`
	Items          []QuarantineItem `json:"items"`
}

// QuarantineFetchCap bounds pagination defensively.
const QuarantineFetchCap = 50000

// ListQuarantineItems returns every quarantined item across the whole
// company for the "computers" service (physical/virtual machines, as
// opposed to the separate "exchange" service). Requires the Quarantine
// API. No filters are applied; the collector groups results by endpoint
// client-side, which is one call instead of one call per endpoint.
func (c *Client) ListQuarantineItems(ctx context.Context) ([]QuarantineItem, error) {
	var all []QuarantineItem
	page := 1
	for {
		var res quarantineListResult
		params := quarantineListParams{Page: page, PerPage: 100}
		if err := c.call(ctx, "quarantine/computers", "getQuarantineItemsList", params, &res); err != nil {
			return nil, err
		}
		all = append(all, res.Items...)
		if !res.HasMoreRecords || len(res.Items) == 0 || len(all) >= QuarantineFetchCap {
			break
		}
		page++
	}
	if len(all) > QuarantineFetchCap {
		all = all[:QuarantineFetchCap]
	}
	return all, nil
}
