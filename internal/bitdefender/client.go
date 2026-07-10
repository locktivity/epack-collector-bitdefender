// Package bitdefender is a minimal client for the Bitdefender GravityZone
// Control Center Public API (JSON-RPC 2.0 over HTTPS, HTTP Basic auth with
// the API key as username and an empty password). Reference:
// https://www.bitdefender.com/business/support/en/77209-125277-public-api.html
package bitdefender

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ErrPermissionDenied is returned when the API key isn't authorized for the
// requested API (JSON-RPC error code -32001, "Authorization error").
var ErrPermissionDenied = errors.New("permission denied")

// ErrNotFound is returned when a request references a resource that
// doesn't exist (JSON-RPC error code -32002, "Resource not found").
var ErrNotFound = errors.New("not found")

// ErrRateLimited is returned on HTTP 429 or JSON-RPC error code -32003
// ("Too many requests"). GravityZone allows a limited number of requests
// per second per API key; see
// https://www.bitdefender.com/business/support/en/77209-125277-public-api.html#UUID-...-api-rate-limits
var ErrRateLimited = errors.New("rate limited")

// JSON-RPC error codes GravityZone uses, per its Public API reference.
const (
	codeAuthorization = -32001
	codeNotFound      = -32002
	codeRateLimited   = -32003
)

// Client is a GravityZone Control Center API client.
type Client struct {
	baseURL    string // e.g. https://cloud.gravityzone.bitdefender.com/api
	authHeader string
	httpClient *http.Client
}

// New creates a Client. baseURL is the Control Center API base URL
// (region- or on-premises-specific, without a trailing slash requirement).
// apiKey is used as the HTTP Basic auth username with an empty password, as
// GravityZone's API requires.
func New(baseURL, apiKey string) *Client {
	token := base64.StdEncoding.EncodeToString([]byte(apiKey + ":"))
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		authHeader: "Basic " + token,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type rpcRequest struct {
	ID      string `json:"id"`
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Details string `json:"details"`
	} `json:"data"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// call issues one JSON-RPC 2.0 request against the given API service (e.g.
// "network", "quarantine/computers") and decodes the result into out. out
// may be nil for methods with no meaningful result.
func (c *Client) call(ctx context.Context, service, method string, params any, out any) error {
	body, err := json.Marshal(rpcRequest{ID: "1", JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("encoding request for %s: %w", method, err)
	}

	url := fmt.Sprintf("%s/v1.0/jsonrpc/%s", c.baseURL, service)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request for %s: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.authHeader)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("%w: %s", ErrRateLimited, method)
	}

	var rr rpcResponse
	if decErr := json.NewDecoder(resp.Body).Decode(&rr); decErr != nil {
		return fmt.Errorf("decoding response for %s (status %d): %w", method, resp.StatusCode, decErr)
	}

	if rr.Error != nil {
		switch rr.Error.Code {
		case codeAuthorization:
			return fmt.Errorf("%w: %s: %s", ErrPermissionDenied, method, rr.Error.Data.Details)
		case codeNotFound:
			return fmt.Errorf("%w: %s: %s", ErrNotFound, method, rr.Error.Data.Details)
		case codeRateLimited:
			return fmt.Errorf("%w: %s", ErrRateLimited, method)
		default:
			return fmt.Errorf("bitdefender API error %d calling %s: %s", rr.Error.Code, method, rr.Error.Message)
		}
	}

	if out == nil || len(rr.Result) == 0 {
		return nil
	}
	if err := json.Unmarshal(rr.Result, out); err != nil {
		return fmt.Errorf("decoding result for %s: %w", method, err)
	}
	return nil
}
