package bitdefender

import (
	"context"
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// QuarantineDetails is the "computers" service's details sub-object for a
// quarantined item. Only filePath is modeled; the full object also carries
// fields like the file's hash, which this collector doesn't use.
type QuarantineDetails struct {
	FilePath string `json:"filePath"`
}

// QuarantineItem is one row from getQuarantineItemsList (Quarantine API,
// "computers" service).
type QuarantineItem struct {
	ID            string             `json:"id"`
	EndpointID    string             `json:"endpointId"`
	ThreatName    string             `json:"threatName"`
	ActionStatus  *int               `json:"actionStatus,omitempty"`
	QuarantinedOn string             `json:"quarantinedOn,omitempty"`
	Details       *QuarantineDetails `json:"details,omitempty"`
}

type quarantineListParams struct {
	Page    int `json:"page"`
	PerPage int `json:"perPage"`
}

type quarantineListResult struct {
	PagesCount int               `json:"pagesCount"`
	Items      *[]QuarantineItem `json:"items"`
}

// QuarantineFetchCap bounds how many quarantined items the collector reads.
const QuarantineFetchCap = 50000

// ListQuarantineItems returns every quarantined item across the whole
// company for the "computers" service (physical/virtual machines, as
// opposed to the separate "exchange" service), 100 per page. The method
// reports pagesCount rather than hasMoreRecords, so pages are read up to
// pagesCount. A company with more items than QuarantineFetchCap fails the
// read rather than be counted in part. Requires the Quarantine API. No
// filters are applied; the collector groups results by endpoint
// client-side, which is one call instead of one call per endpoint.
func (c *Client) ListQuarantineItems(ctx context.Context) ([]QuarantineItem, error) {
	const method = "getQuarantineItemsList"
	all := []QuarantineItem{}
	for page := 1; ; page++ {
		var res quarantineListResult
		if err := c.call(ctx, "v1.0", "quarantine/computers", method, quarantineListParams{Page: page, PerPage: 100}, &res); err != nil {
			return nil, err
		}
		if res.Items == nil {
			return nil, invalidResponse(method, "has no items list")
		}
		all = append(all, *res.Items...)
		if page >= res.PagesCount || len(*res.Items) == 0 {
			return all, nil
		}
		if len(all) >= QuarantineFetchCap {
			return nil, componentsdk.CodeError(componentsdk.CodeTooLarge,
				fmt.Errorf("GravityZone lists more than %d quarantined items, more than the collector reads", QuarantineFetchCap))
		}
	}
}
