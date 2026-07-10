package bitdefender

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c := New(srv.URL, "test-api-key")
	c.retryDelay = func(int) time.Duration { return 0 }
	return srv, c
}

func rpcOK(t *testing.T, w http.ResponseWriter, result any) {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"result":  json.RawMessage(raw),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func rpcErr(t *testing.T, w http.ResponseWriter, code int, message, details string) {
	t.Helper()
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"error": map[string]any{
			"code":    code,
			"message": message,
			"data":    map[string]any{"details": details},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func TestClient_AuthHeader(t *testing.T) {
	var gotAuth string
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		rpcOK(t, w, endpointsListResult{})
	})

	_, _ = c.ListEndpoints(context.Background(), "")
	if gotAuth == "" {
		t.Fatal("expected Authorization header")
	}
	if gotAuth[:6] != "Basic " {
		t.Errorf("Authorization = %q, want Basic prefix", gotAuth)
	}
}

func TestClient_SuccessfulCall(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		rpcOK(t, w, endpointsListResult{
			Total: 1,
			Items: []Endpoint{{ID: "ep-1", Name: "laptop-1"}},
		})
	})

	endpoints, err := c.ListEndpoints(context.Background(), "")
	if err != nil {
		t.Fatalf("ListEndpoints error: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].ID != "ep-1" {
		t.Errorf("got %v, want 1 endpoint with ID ep-1", endpoints)
	}
}

func TestClient_RPCPermissionDenied(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		rpcErr(t, w, codeAuthorization, "Authorization error", "Network API not enabled")
	})

	_, err := c.ListEndpoints(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Errorf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestClient_RPCNotFound(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		rpcErr(t, w, codeNotFound, "Resource not found", "endpoint abc not found")
	})

	_, err := c.GetManagedEndpointDetails(context.Background(), "abc")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestClient_RPCRateLimited_RetriesAndFails(t *testing.T) {
	var callCount atomic.Int32
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		rpcErr(t, w, codeRateLimited, "Too many requests", "")
	})

	_, err := c.ListEndpoints(context.Background(), "")
	if err == nil {
		t.Fatal("expected error after max retries")
	}
	if callCount.Load() != int32(maxAttempts) {
		t.Errorf("expected %d attempts, got %d", maxAttempts, callCount.Load())
	}
}

func TestClient_RPCRateLimited_EventualSuccess(t *testing.T) {
	var callCount atomic.Int32
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n <= 2 {
			rpcErr(t, w, codeRateLimited, "Too many requests", "")
			return
		}
		rpcOK(t, w, endpointsListResult{
			Total: 1,
			Items: []Endpoint{{ID: "ep-1"}},
		})
	})

	endpoints, err := c.ListEndpoints(context.Background(), "")
	if err != nil {
		t.Fatalf("ListEndpoints error: %v", err)
	}
	if len(endpoints) != 1 {
		t.Errorf("got %d endpoints, want 1", len(endpoints))
	}
	if callCount.Load() != 3 {
		t.Errorf("expected 3 calls (2 retries + success), got %d", callCount.Load())
	}
}

func TestClient_HTTP429_Retries(t *testing.T) {
	var callCount atomic.Int32
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("rate limited"))
			return
		}
		rpcOK(t, w, endpointsListResult{
			Total: 1,
			Items: []Endpoint{{ID: "ep-1"}},
		})
	})

	endpoints, err := c.ListEndpoints(context.Background(), "")
	if err != nil {
		t.Fatalf("ListEndpoints error: %v", err)
	}
	if len(endpoints) != 1 {
		t.Errorf("got %d endpoints, want 1", len(endpoints))
	}
	if callCount.Load() != 2 {
		t.Errorf("expected 2 calls (1 retry), got %d", callCount.Load())
	}
}

func TestClient_HTTP500_Retries(t *testing.T) {
	var callCount atomic.Int32
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal error"))
			return
		}
		rpcOK(t, w, endpointsListResult{Items: []Endpoint{{ID: "ep-1"}}})
	})

	endpoints, err := c.ListEndpoints(context.Background(), "")
	if err != nil {
		t.Fatalf("ListEndpoints error: %v", err)
	}
	if len(endpoints) != 1 {
		t.Errorf("got %d endpoints, want 1", len(endpoints))
	}
}

func TestClient_HTTP400_NoRetry(t *testing.T) {
	var callCount atomic.Int32
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	})

	_, err := c.ListEndpoints(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for 400")
	}
	if callCount.Load() != 1 {
		t.Errorf("expected 1 call (no retry for 400), got %d", callCount.Load())
	}
}

func TestClient_MalformedJSON(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	})

	_, err := c.ListEndpoints(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestClient_NullResult(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","result":null}`))
	})

	var out endpointsListResult
	err := c.call(context.Background(), "network", "getEndpointsList", nil, &out)
	if err != nil {
		t.Fatalf("expected nil error for null result, got: %v", err)
	}
	if out.Total != 0 {
		t.Errorf("expected zero-value result, got total=%d", out.Total)
	}
}

func TestClient_EmptyResult(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1"}`))
	})

	var out endpointsListResult
	err := c.call(context.Background(), "network", "getEndpointsList", nil, &out)
	if err != nil {
		t.Fatalf("expected nil error for missing result field, got: %v", err)
	}
}

func TestClient_RPCErrorWithoutData(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"1","error":{"code":-32600,"message":"Invalid Request"}}`))
	})

	_, err := c.ListEndpoints(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrRateLimited) {
		t.Errorf("expected generic API error, got sentinel: %v", err)
	}
}

func TestClient_ContextCanceled(t *testing.T) {
	_, c := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		rpcOK(t, w, endpointsListResult{})
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.ListEndpoints(ctx, "")
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}
