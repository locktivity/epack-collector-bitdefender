package collector

import (
	"context"
	"fmt"

	"github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"
	"github.com/locktivity/epack/componentsdk"
)

// Config configures a collection run.
type Config struct {
	// BaseURL is the GravityZone Control Center API base URL, e.g.
	// "https://cloud.gravityzone.bitdefender.com/api" (US/global) or
	// "https://cloudgz.gravityzone.bitdefender.com/api" (EU), or your
	// on-premises Control Center's API URL.
	BaseURL string
	// APIKey is the GravityZone API key. It must have the Network API
	// enabled for trust/audit, and additionally the Quarantine API for the
	// internal-level quarantine surface. Generated under My Account > API
	// keys in Control Center.
	APIKey string
	// ParentGroupID optionally scopes collection to a single network
	// group (and its descendants) instead of the whole company.
	ParentGroupID string

	OnStatus   func(string)
	OnProgress func(current, total int64, message string)
}

// bdClient is the subset of *bitdefender.Client this package depends on, so
// tests can substitute a mock instead of hitting the real API.
type bdClient interface {
	ListEndpoints(ctx context.Context, parentID string) ([]bitdefender.Endpoint, error)
	GetManagedEndpointDetails(ctx context.Context, endpointID string) (*bitdefender.EndpointDetail, error)
	ListQuarantineItems(ctx context.Context) ([]bitdefender.QuarantineItem, error)
}

// Collector collects Bitdefender GravityZone endpoint posture.
type Collector struct {
	config Config
	client bdClient
}

// New creates a Collector backed by the real GravityZone API.
func New(config Config) (*Collector, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("api key is required")
	}
	if config.BaseURL == "" {
		return nil, fmt.Errorf("base url is required")
	}
	return &Collector{
		config: config,
		client: bitdefender.New(config.BaseURL, config.APIKey),
	}, nil
}

// NewWithClient creates a Collector backed by a caller-supplied client,
// for tests.
func NewWithClient(config Config, client bdClient) *Collector {
	return &Collector{config: config, client: client}
}

func (c *Collector) status(msg string) {
	if c.config.OnStatus != nil {
		c.config.OnStatus(msg)
	}
}

// Collect runs one collection pass at the given level. It always returns
// the trust-level compliance percentage even if audit/internal surfaces
// degrade; a hard failure to list endpoints at all is the only case that
// returns an error, since every other surface derives from that list.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*EndpointPosture, error) {
	posture := &EndpointPosture{CollectedAtLevel: string(level)}
	diag := &diagnostics{}

	c.status("Fetching managed endpoints...")
	endpoints, err := c.client.ListEndpoints(ctx, c.config.ParentGroupID)
	if err != nil {
		return nil, fmt.Errorf("listing endpoints: %w", err)
	}

	laptops := filterComputers(endpoints)
	posture.Scope.TotalManagedComputers = len(laptops)
	posture.Compliance = summarizeCompliance(laptops)

	p := &collectionPass{
		ctx:     ctx,
		posture: posture,
		diag:    diag,
		level:   level,
		laptops: laptops,
	}

	if level.AtLeast(componentsdk.LevelAudit) {
		c.status("Building endpoint inventory...")
		c.collectEndpoints(p)
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		c.status("Fetching per-endpoint policy and module detail...")
		c.collectPolicies(p)
		c.status("Fetching quarantine items...")
		c.collectQuarantine(p)
	}

	posture.Diagnostics = diag.toDiagnostics()
	c.status("Collection complete")
	return posture, nil
}
