// epack-collector-bitdefender collects endpoint compliance posture from
// Bitdefender GravityZone (laptop/desktop compliance, quarantine activity,
// and enforced policies).
//
// This binary is designed to be executed by the epack collector runner.
// It uses the epack Component SDK for protocol compliance.
package main

import (
	"github.com/locktivity/epack-collector-bitdefender/internal/collector"
	"github.com/locktivity/epack/componentsdk"
)

// Build-time variables set via -ldflags
var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "bitdefender",
		Version:     Version,
		Commit:      Commit,
		Description: "Collects endpoint compliance posture from Bitdefender GravityZone",
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()
	config := collector.Config{
		BaseURL:       getString(cfg, "base_url"),
		APIKey:        ctx.Secret("BITDEFENDER_API_KEY"),
		ParentGroupID: getString(cfg, "parent_group_id"),
		OnStatus:      ctx.Status,
		OnProgress:    ctx.Progress,
	}

	if config.BaseURL == "" {
		return componentsdk.NewConfigError("base_url is required, e.g. https://cloud.gravityzone.bitdefender.com/api")
	}
	if config.APIKey == "" {
		return componentsdk.NewConfigError("authentication required: provide BITDEFENDER_API_KEY")
	}

	c, err := collector.New(config)
	if err != nil {
		return componentsdk.NewConfigError("creating collector: %v", err)
	}

	posture, err := c.Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return componentsdk.NewNetworkError("collecting posture: %v", err)
	}

	return ctx.Emit([]componentsdk.CollectedArtifact{
		{
			Data: posture,
			Path: "artifacts/bitdefender.json",
		},
	})
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
