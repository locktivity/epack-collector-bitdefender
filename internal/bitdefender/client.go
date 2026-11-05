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
	"net/url"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// JSON-RPC error codes GravityZone documents beyond the JSON-RPC 2.0 ones
// (-32700, -32600, -32601, -32602). Each comes in an HTTP 200 response
// except -32003, which comes with HTTP 429.
const (
	codeServerError   = -32000
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

// New creates a Client that sends its calls through httpClient. baseURL is
// the Control Center API base URL (region- or on-premises-specific). apiKey
// is used as the HTTP Basic auth username with an empty password, as
// GravityZone's API requires.
func New(httpClient *http.Client, baseURL, apiKey string) *Client {
	token := base64.StdEncoding.EncodeToString([]byte(apiKey + ":"))
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		authHeader: "Basic " + token,
		httpClient: httpClient,
	}
}

// Host returns the host of baseURL, the only host that may receive the API
// key, or "" when baseURL names none.
func Host(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// OperationName names the calls to one JSON-RPC method of one API service,
// such as "bitdefender.network.getEndpointsList", in the run's call ledger.
func OperationName(service, method string) string {
	return "bitdefender." + strings.ReplaceAll(service, "/", ".") + "." + method
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

// APIError is a GravityZone answer that carries no result: an HTTP status
// other than 200, or a JSON-RPC error object.
type APIError struct {
	Method string
	Status int
	Header http.Header
	// RPCCode is the JSON-RPC error code, or 0 when the response had none.
	RPCCode int
	Message string
	Details string
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "GravityZone %s", e.Method)
	if e.Status != http.StatusOK {
		fmt.Fprintf(&b, " returned HTTP %d", e.Status)
	}
	if e.RPCCode != 0 {
		fmt.Fprintf(&b, " error %d %s", e.RPCCode, e.Message)
		if e.Details != "" {
			fmt.Fprintf(&b, ": %s", e.Details)
		}
	}
	return b.String()
}

// HTTPStatus, HTTPHeader, and VendorCode let componentsdk.Classify read the
// status and throttle headers, and give records the JSON-RPC error code.
func (e *APIError) HTTPStatus() int         { return e.Status }
func (e *APIError) HTTPHeader() http.Header { return e.Header }
func (e *APIError) VendorCode() string {
	if e.RPCCode == 0 {
		return ""
	}
	return strconv.Itoa(e.RPCCode)
}

// rpcCode is the code for a JSON-RPC error that came in an HTTP 200
// response: the code of the HTTP status the error stands in for.
func rpcCode(code int) componentsdk.Code {
	switch code {
	case codeAuthorization:
		return componentsdk.CodePermissionDenied
	case codeRateLimited:
		return componentsdk.CodeRateLimited
	case codeServerError:
		return componentsdk.CodeVendorError
	default:
		return componentsdk.CodeInvalidResponse
	}
}

// ClassifyResponse gives a JSON-RPC error in an HTTP 200 response its code,
// so the SDK's transport retries a throttle or a server error there as it
// would a 429 or a 5xx. Other statuses keep the code their status gives.
// Pass it as componentsdk.HTTPOptions.ClassifyResponse with ClassifySuccess
// set.
func ClassifyResponse(resp *http.Response, body []byte) (componentsdk.Code, bool) {
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	var rr struct {
		Error *rpcError `json:"error"`
	}
	if json.Unmarshal(body, &rr) != nil || rr.Error == nil {
		return "", false
	}
	return rpcCode(rr.Error.Code), true
}

// rpcErrorCode returns the JSON-RPC error code of an error GravityZone sent
// in an HTTP 200 response, or 0 for any other error.
func rpcErrorCode(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusOK {
		return apiErr.RPCCode
	}
	return 0
}

// NotFound reports whether GravityZone answered that a resource the call
// named does not exist or is not accessible.
func NotFound(err error) bool {
	return rpcErrorCode(err) == codeNotFound
}

// Permission returns the API a GravityZone API key must have enabled to call
// a service, as getApiKeyDetails lists it in enabledApis, such as "network".
// The General API's getApiKeyDetails needs none, so its service returns "".
func Permission(service string) string {
	switch {
	case service == "network":
		return "network"
	case strings.HasPrefix(service, "quarantine/"):
		return "quarantine"
	}
	return ""
}

// call sends one JSON-RPC 2.0 request to an API service (such as "network"
// or "quarantine/computers") at an API version (such as "v1.0") and decodes
// the result into out. Every method this client calls only reads, so each
// call is marked safe to retry, and the SDK's transport retries it. Errors
// built from the response carry the call, so each gap recorded from one
// includes the operation and, for a denial, the API the key lacks.
func (c *Client) call(ctx context.Context, version, service, method string, params, out any) error {
	body, err := json.Marshal(rpcRequest{ID: "1", JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("encoding the request for %s: %w", method, err)
	}
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: OperationName(service, method), Safe: true, Permission: Permission(service)})
	endpoint := c.baseURL + "/" + version + "/jsonrpc/" + service
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building the request for %s: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", c.authHeader)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var rr rpcResponse
	decodeErr := json.NewDecoder(resp.Body).Decode(&rr)
	if resp.StatusCode != http.StatusOK {
		apiErr := &APIError{Method: method, Status: resp.StatusCode, Header: resp.Header}
		if decodeErr == nil && rr.Error != nil {
			apiErr.RPCCode, apiErr.Message, apiErr.Details = rr.Error.Code, rr.Error.Message, rr.Error.Data.Details
		}
		return componentsdk.ResponseError(resp, apiErr)
	}
	if decodeErr != nil {
		return componentsdk.ResponseError(resp, fmt.Errorf("decoding the response to %s: %w", method, decodeErr))
	}
	if rr.Error != nil {
		apiErr := &APIError{Method: method, Status: resp.StatusCode, Header: resp.Header,
			RPCCode: rr.Error.Code, Message: rr.Error.Message, Details: rr.Error.Data.Details}
		return componentsdk.ResponseError(resp, componentsdk.CodeError(rpcCode(rr.Error.Code), apiErr))
	}
	if len(rr.Result) == 0 || string(rr.Result) == "null" {
		return componentsdk.ResponseError(resp, invalidResponse(method, "has no result"))
	}
	if err := json.Unmarshal(rr.Result, out); err != nil {
		return componentsdk.ResponseError(resp, fmt.Errorf("decoding the result of %s: %w", method, err))
	}
	return nil
}

// invalidResponse reports a response that lacks what the collector reads
// from it.
func invalidResponse(method, problem string) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("the response to %s %s", method, problem))
}
