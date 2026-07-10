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
	"io"
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
	retryDelay func(attempt int) time.Duration // defaults to backoff; override in tests
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
		retryDelay: backoff,
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
// may be nil for methods with no meaningful result. Retries on transient
// HTTP errors (429, 5xx) and JSON-RPC rate-limit errors with exponential
// backoff.
func (c *Client) call(ctx context.Context, service, method string, params any, out any) error {
	body, err := json.Marshal(rpcRequest{ID: "1", JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("encoding request for %s: %w", method, err)
	}

	url := fmt.Sprintf("%s/v1.0/jsonrpc/%s", c.baseURL, service)

	var lastErr error
	for attempt := range maxAttempts {
		err := c.doCall(ctx, url, method, body, out)
		if err == nil {
			return nil
		}

		if !isCallRetryable(err) {
			return err
		}

		lastErr = err
		if sleepErr := sleep(ctx, c.retryDelay(attempt)); sleepErr != nil {
			return sleepErr
		}
	}
	return fmt.Errorf("max retries exceeded for %s: %w", method, lastErr)
}

func (c *Client) doCall(ctx context.Context, url, method string, body []byte, out any) error {
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		if isRetryable(resp.StatusCode) {
			return &retryableError{
				msg: fmt.Sprintf("HTTP %d calling %s: %s", resp.StatusCode, method, string(respBody)),
			}
		}
		return fmt.Errorf("HTTP %d calling %s: %s", resp.StatusCode, method, string(respBody))
	}

	var rr rpcResponse
	if decErr := json.NewDecoder(resp.Body).Decode(&rr); decErr != nil {
		return fmt.Errorf("decoding response for %s: %w", method, decErr)
	}

	if rr.Error != nil {
		return classifyRPCError(method, rr.Error)
	}

	if out == nil {
		return nil
	}
	if len(rr.Result) == 0 || string(rr.Result) == "null" {
		return nil
	}
	if err := json.Unmarshal(rr.Result, out); err != nil {
		return fmt.Errorf("decoding result for %s: %w", method, err)
	}
	return nil
}

type retryableError struct {
	msg string
}

func (e *retryableError) Error() string { return e.msg }

func classifyRPCError(method string, rpcErr *rpcError) error {
	switch rpcErr.Code {
	case codeAuthorization:
		return fmt.Errorf("%w: %s: %s", ErrPermissionDenied, method, rpcErr.Data.Details)
	case codeNotFound:
		return fmt.Errorf("%w: %s: %s", ErrNotFound, method, rpcErr.Data.Details)
	case codeRateLimited:
		return &retryableError{
			msg: fmt.Sprintf("%s: %s", ErrRateLimited.Error(), method),
		}
	default:
		return fmt.Errorf("bitdefender API error %d calling %s: %s", rpcErr.Code, method, rpcErr.Message)
	}
}

func isCallRetryable(err error) bool {
	var re *retryableError
	return errors.As(err, &re)
}
