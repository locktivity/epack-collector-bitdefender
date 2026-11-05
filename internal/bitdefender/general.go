package bitdefender

import (
	"context"

	"github.com/locktivity/epack/componentsdk"
)

// APIKeyDetails is what getApiKeyDetails reports about the API key.
type APIKeyDetails struct {
	// EnabledAPIs lists the APIs the key may call, such as "network".
	EnabledAPIs []string
}

// GetAPIKeyDetails reads the API key's details from the General API. The
// collector calls it first, as its sign-in.
func (c *Client) GetAPIKeyDetails(ctx context.Context) (*APIKeyDetails, error) {
	const method = "getApiKeyDetails"
	var out struct {
		EnabledAPIs *[]string `json:"enabledApis"`
	}
	if err := c.call(ctx, "v1.0", "general", method, struct{}{}, &out); err != nil {
		// getApiKeyDetails needs no API enabled on the key, so an
		// authorization error here means GravityZone rejected the key itself.
		if rpcErrorCode(err) == codeAuthorization {
			return nil, componentsdk.CodeError(componentsdk.CodeAuthFailed, err)
		}
		return nil, err
	}
	if out.EnabledAPIs == nil {
		return nil, invalidResponse(method, "has no enabledApis list")
	}
	return &APIKeyDetails{EnabledAPIs: *out.EnabledAPIs}, nil
}
