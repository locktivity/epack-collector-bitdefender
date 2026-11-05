package collector

import (
	"time"

	"github.com/locktivity/epack-collector-bitdefender/docs/schema"
	"github.com/locktivity/epack-collector-bitdefender/internal/bitdefender"
	"github.com/locktivity/epack/componentsdk"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        collectorName,
		Version:     version,
		Commit:      commit,
		Description: "Collects endpoint compliance posture from Bitdefender GravityZone",
		// At every level the collector calls getManagedEndpointDetails once
		// per computer with the agent, under GravityZone's rate limits. That
		// takes minutes for a large fleet. A runner's EPACK_DEADLINE shortens
		// this.
		Timeout:  30 * time.Minute,
		Schemas:  schema.Schemas(),
		Methods:  schema.Methods(),
		TraceMap: schema.TraceMap,
		Writes:   []string{normalizedSchema},
	}
}

// Run is the collector's handler. It fails only for invalid configuration or
// a failed sign-in, and otherwise emits what it collected with a gap recorded
// for each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()
	config := Config{
		BaseURL:       getString(cfg, "base_url"),
		APIKey:        ctx.Secret("BITDEFENDER_API_KEY"),
		ParentGroupID: getString(cfg, "parent_group_id"),
		Recorder:      componentsdk.Records(ctx),
		Now:           func() time.Time { return componentsdk.Now(ctx) },
		Selected:      func(at componentsdk.Location) bool { return componentsdk.Selected(ctx, at) },
		OnStatus:      ctx.Status,
		OnProgress:    ctx.Progress,
	}
	if err := config.Validate(); err != nil {
		return err
	}
	config.HTTPClient = componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts:  []string{bitdefender.Host(config.BaseURL)},
		ClassifyResponse: bitdefender.ClassifyResponse,
		ClassifySuccess:  true,
	})

	posture, err := New(config).Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return err
	}
	return ctx.Emit(Artifacts(posture))
}

// Artifacts returns the detailed artifact and, when the run built it, the
// normalized endpoint-posture artifact.
func Artifacts(posture *EndpointPosture) []componentsdk.CollectedArtifact {
	artifacts := []componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(artifactPath, posture, componentsdk.ArtifactMeta{}),
	}
	if n := posture.Normalized(); n != nil {
		artifacts = append(artifacts, componentsdk.JSONArtifact(normalizedPath, n, componentsdk.ArtifactMeta{Schema: normalizedSchema}))
	}
	return artifacts
}

// getString safely extracts a string from config map.
func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}
