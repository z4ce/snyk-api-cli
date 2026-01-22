package cmd

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewHTTPClient(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
	}{
		{
			name:            "default timeout when zero",
			timeout:         0,
			expectedTimeout: DefaultTimeout,
		},
		{
			name:            "custom timeout",
			timeout:         60 * time.Second,
			expectedTimeout: 60 * time.Second,
		},
		{
			name:            "short timeout",
			timeout:         5 * time.Second,
			expectedTimeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewHTTPClient(tt.timeout)
			if client.Timeout != tt.expectedTimeout {
				t.Errorf("NewHTTPClient(%v).Timeout = %v, want %v", tt.timeout, client.Timeout, tt.expectedTimeout)
			}
		})
	}
}

func TestExecuteAPIRequest_GET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		if r.Method != "GET" {
			t.Errorf("Expected GET, got %s", r.Method)
		}

		// Verify user agent
		if r.Header.Get("User-Agent") != DefaultUserAgent {
			t.Errorf("Expected User-Agent %s, got %s", DefaultUserAgent, r.Header.Get("User-Agent"))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := ExecuteAPIRequest(RequestOptions{
		Method: "GET",
		URL:    server.URL,
	})

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}

	if !strings.Contains(output, `{"success":true}`) {
		t.Errorf("Expected response body in output, got: %s", output)
	}
}

func TestExecuteAPIRequest_POST_WithBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Verify content type
		if r.Header.Get("Content-Type") != DefaultContentType {
			t.Errorf("Expected Content-Type %s, got %s", DefaultContentType, r.Header.Get("Content-Type"))
		}

		// Read body
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"data":"test"}` {
			t.Errorf("Expected body {\"data\":\"test\"}, got %s", string(body))
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"created":true}`))
	}))
	defer server.Close()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := ExecuteAPIRequest(RequestOptions{
		Method: "POST",
		URL:    server.URL,
		Body:   `{"data":"test"}`,
	})

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}
}

func TestExecuteAPIRequest_CustomContentType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify custom content type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         server.URL,
		Body:        `{}`,
		ContentType: "application/json",
	})

	w.Close()
	os.Stdout = oldStdout

	io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}
}

func TestExecuteAPIRequest_CustomUserAgent(t *testing.T) {
	customAgent := "custom-agent/2.0"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != customAgent {
			t.Errorf("Expected User-Agent %s, got %s", customAgent, r.Header.Get("User-Agent"))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := ExecuteAPIRequest(RequestOptions{
		Method:    "GET",
		URL:       server.URL,
		UserAgent: customAgent,
	})

	w.Close()
	os.Stdout = oldStdout

	io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}
}

func TestExecuteAPIRequest_VerboseOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Capture stderr for verbose output
	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	// Capture stdout
	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	err := ExecuteAPIRequest(RequestOptions{
		Method:  "GET",
		URL:     server.URL,
		Verbose: true,
	})

	wErr.Close()
	wOut.Close()
	os.Stderr = oldStderr
	os.Stdout = oldStdout

	var bufErr bytes.Buffer
	io.Copy(&bufErr, rErr)
	stderrOutput := bufErr.String()

	io.Copy(io.Discard, rOut)

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}

	// Check for verbose output
	expectedPhrases := []string{
		"* Requesting GET",
		"* Checking authentication options",
		"* Making request...",
		"* Response:",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(stderrOutput, phrase) {
			t.Errorf("Expected verbose output to contain %q, got: %s", phrase, stderrOutput)
		}
	}
}

func TestExecuteAPIRequest_SilentMode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"should not appear"}`))
	}))
	defer server.Close()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := ExecuteAPIRequest(RequestOptions{
		Method: "GET",
		URL:    server.URL,
		Silent: true,
	})

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}

	if output != "" {
		t.Errorf("Expected no output in silent mode, got: %s", output)
	}
}

func TestExecuteAPIRequest_IncludeResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         server.URL,
		IncludeResp: true,
	})

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}

	if !strings.Contains(output, "HTTP/") {
		t.Errorf("Expected HTTP version in output, got: %s", output)
	}

	if !strings.Contains(output, "X-Custom-Header") {
		t.Errorf("Expected custom header in output, got: %s", output)
	}
}

func TestExecuteAPIRequest_ErrorResponse_PrintsRequestID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(SnykRequestIDHeader, "test-request-id-12345")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"Bad Request"}`))
	}))
	defer server.Close()

	// Capture stderr
	oldStderr := os.Stderr
	rErr, wErr, _ := os.Pipe()
	os.Stderr = wErr

	// Capture stdout
	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	_ = ExecuteAPIRequest(RequestOptions{
		Method: "GET",
		URL:    server.URL,
	})

	wErr.Close()
	wOut.Close()
	os.Stderr = oldStderr
	os.Stdout = oldStdout

	var bufErr bytes.Buffer
	io.Copy(&bufErr, rErr)
	stderrOutput := bufErr.String()

	io.Copy(io.Discard, rOut)

	if !strings.Contains(stderrOutput, "Snyk-Request-Id: test-request-id-12345") {
		t.Errorf("Expected Snyk-Request-Id in stderr, got: %s", stderrOutput)
	}
}

func TestExecuteAPIRequest_DELETE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("Expected DELETE, got %s", r.Method)
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := ExecuteAPIRequest(RequestOptions{
		Method: "DELETE",
		URL:    server.URL,
	})

	w.Close()
	os.Stdout = oldStdout

	io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}
}

func TestExecuteAPIRequest_PUT(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT, got %s", r.Method)
		}

		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"updated":true}` {
			t.Errorf("Expected body, got %s", string(body))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := ExecuteAPIRequest(RequestOptions{
		Method: "PUT",
		URL:    server.URL,
		Body:   `{"updated":true}`,
	})

	w.Close()
	os.Stdout = oldStdout

	io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}
}

func TestExecuteAPIRequest_PATCH(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PATCH" {
			t.Errorf("Expected PATCH, got %s", r.Method)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := ExecuteAPIRequest(RequestOptions{
		Method: "PATCH",
		URL:    server.URL,
		Body:   `{"field":"value"}`,
	})

	w.Close()
	os.Stdout = oldStdout

	io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}
}

func TestExecuteAPIRequest_DefaultsApplied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify defaults are applied
		if r.Header.Get("User-Agent") != DefaultUserAgent {
			t.Errorf("Expected default User-Agent %s, got %s", DefaultUserAgent, r.Header.Get("User-Agent"))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Call with minimal options - defaults should be applied
	err := ExecuteAPIRequest(RequestOptions{
		Method: "GET",
		URL:    server.URL,
	})

	w.Close()
	os.Stdout = oldStdout

	io.Copy(io.Discard, r)

	if err != nil {
		t.Errorf("ExecuteAPIRequest() error = %v", err)
	}
}
