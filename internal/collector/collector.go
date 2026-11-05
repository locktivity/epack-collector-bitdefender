package collector

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"
	"github.com/locktivity/epack/componentsdk"
)

// collectorName is the collector's name, which its artifact paths start
// with.
const collectorName = "bitdefender"

// artifactPath is the path of the collector's detailed artifact in the pack,
// as componentsdk.ArtifactPath("bitdefender", "") returns it.
const artifactPath = "artifacts/bitdefender.details.json"

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

	// HTTPClient sends the calls; Run builds it with
	// componentsdk.NewHTTPClient.
	HTTPClient *http.Client
	// Recorder takes the values left out and the identity signed in as.
	Recorder *componentsdk.Recorder
	// Now gives the run's time. It defaults to time.Now.
	Now func() time.Time
	// Selected reports whether the run collects the artifact at a location,
	// as componentsdk.Selected does. It defaults to collecting every
	// artifact.
	Selected func(componentsdk.Location) bool

	OnStatus   func(string)
	OnProgress func(current, total int64, message string)
}

// Validate checks the configuration before any call is made.
func (c Config) Validate() error {
	if c.BaseURL == "" {
		return componentsdk.NewConfigError("base_url is required, e.g. https://cloud.gravityzone.bitdefender.com/api")
	}
	if u, err := url.Parse(c.BaseURL); err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return componentsdk.NewConfigError("base_url must be an https URL, e.g. https://cloud.gravityzone.bitdefender.com/api")
	}
	if c.APIKey == "" {
		return componentsdk.NewConfigError("authentication required: provide BITDEFENDER_API_KEY")
	}
	return nil
}

// bdClient is the subset of *bitdefender.Client this package depends on, so
// tests can substitute a mock instead of hitting the real API.
type bdClient interface {
	GetAPIKeyDetails(ctx context.Context) (*bitdefender.APIKeyDetails, error)
	ListEndpoints(ctx context.Context, parentID string, scanLogs bool) ([]bitdefender.Endpoint, error)
	FindActiveDirectoryFolders(ctx context.Context) ([]string, error)
	ListInventoryEndpoints(ctx context.Context, parentID string, scanLogs bool) ([]bitdefender.Endpoint, error)
	GetManagedEndpointDetails(ctx context.Context, endpointID string) (*bitdefender.EndpointDetail, error)
	ListQuarantineItems(ctx context.Context) ([]bitdefender.QuarantineItem, error)
}

// Collector collects Bitdefender GravityZone endpoint posture.
type Collector struct {
	config Config
	client bdClient
	rec    *componentsdk.Recorder
}

// New creates a Collector backed by the real GravityZone API.
func New(config Config) *Collector {
	return NewWithClient(config, bitdefender.New(config.HTTPClient, config.BaseURL, config.APIKey))
}

// NewWithClient creates a Collector backed by a caller-supplied client,
// for tests.
func NewWithClient(config Config, client bdClient) *Collector {
	rec := config.Recorder
	if rec == nil {
		rec = &componentsdk.Recorder{}
	}
	return &Collector{config: config, client: client, rec: rec}
}

func (c *Collector) status(msg string) {
	if c.config.OnStatus != nil {
		c.config.OnStatus(msg)
	}
}

func (c *Collector) progress(current, total int64, msg string) {
	if c.config.OnProgress != nil {
		c.config.OnProgress(current, total, msg)
	}
}

func (c *Collector) now() time.Time {
	if c.config.Now != nil {
		return c.config.Now()
	}
	return time.Now()
}

func (c *Collector) selected(at componentsdk.Location) bool {
	return c.config.Selected == nil || c.config.Selected(at)
}

// at locates a value in the artifact.
func at(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: artifactPath, Pointer: pointer}
}

// Collect runs one collection pass at the given level. It returns an error
// only when the sign-in fails or GravityZone does not know the configured
// parent group. Any value it cannot read after that is left out of the
// artifact and recorded as a gap. The normalized endpoint-posture artifact
// is on the result, from Normalized.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*EndpointPosture, error) {
	c.status("Signing in to GravityZone...")
	if err := c.signIn(ctx); err != nil {
		return nil, err
	}

	posture := &EndpointPosture{CollectedAtLevel: string(level)}
	internal := level.AtLeast(componentsdk.LevelInternal)
	details := c.selected(componentsdk.Location{Path: artifactPath})
	normalized := c.selected(componentsdk.Location{Path: normalizedPath, Schema: normalizedSchema})
	if !details && !normalized {
		c.status("Collection complete")
		return posture, nil
	}

	c.status("Fetching endpoints...")
	endpoints, err := c.client.ListEndpoints(ctx, c.config.ParentGroupID, internal)
	if err != nil && c.config.ParentGroupID != "" && bitdefender.NotFound(err) {
		return nil, componentsdk.NewConfigError("parent_group_id %q is not a group GravityZone can find: %v", c.config.ParentGroupID, err)
	}
	p := &collectionPass{
		ctx:     ctx,
		posture: posture,
		diag:    &diagnostics{},
		level:   level,
		listErr: err,
	}
	if err != nil {
		p.diag.surfaceFailed("endpoints", "Network", "could not list endpoints", err)
	} else {
		c.status("Fetching Active Directory endpoints...")
		inventory, adErr := c.listActiveDirectory(ctx, internal)
		if adErr != nil {
			p.adErr = adErr
			p.diag.surfaceFailed("endpoints", "Network", "could not list the endpoints in the Active Directory folder", adErr)
		}
		endpoints = mergeEndpoints(endpoints, inventory)
	}
	p.all = endpoints
	p.computers = filterComputers(endpoints)

	if normalized || (internal && details) {
		c.status("Fetching endpoint details...")
		c.readDetails(p)
	}

	c.summarizeCompliance(p)
	if level.AtLeast(componentsdk.LevelAudit) {
		c.status("Building endpoint inventory...")
		c.collectEndpoints(p)
	}
	if internal && details {
		c.collectPolicies(p)
		c.status("Fetching quarantine items...")
		c.collectQuarantine(p)
	}

	p.posture.Diagnostics = p.diag.toDiagnostics()
	if normalized {
		p.posture.normalized = c.buildNormalized(p)
	}
	c.status("Collection complete")
	return p.posture, nil
}

// signIn proves the API key works before any surface is read. It is the
// only call whose failure fails the run.
func (c *Collector) signIn(ctx context.Context) error {
	details, err := c.client.GetAPIKeyDetails(ctx)
	if err != nil {
		return fmt.Errorf("signing in to GravityZone: %w", err)
	}
	c.rec.SignedInAs(componentsdk.Principal{
		Provider: "bitdefender-gravityzone",
		Kind:     "api_key",
		Scopes:   details.EnabledAPIs,
	})
	return nil
}
