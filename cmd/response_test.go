package cmd

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestIsErrorStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{"200 OK", 200, false},
		{"201 Created", 201, false},
		{"204 No Content", 204, false},
		{"299 edge case", 299, false},
		{"300 redirect", 300, true},
		{"301 Moved Permanently", 301, true},
		{"400 Bad Request", 400, true},
		{"401 Unauthorized", 401, true},
		{"403 Forbidden", 403, true},
		{"404 Not Found", 404, true},
		{"500 Internal Server Error", 500, true},
		{"502 Bad Gateway", 502, true},
		{"503 Service Unavailable", 503, true},
		{"199 below success range", 199, true},
		{"100 Continue", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isErrorStatusCode(tt.statusCode)
			if result != tt.expected {
				t.Errorf("isErrorStatusCode(%d) = %v, want %v", tt.statusCode, result, tt.expected)
			}
		})
	}
}

func TestPrintSnykRequestID(t *testing.T) {
	tests := []struct {
		name           string
		requestID      string
		expectedOutput string
	}{
		{
			name:           "with request ID",
			requestID:      "abc123-def456-ghi789",
			expectedOutput: "Snyk-Request-Id: abc123-def456-ghi789\n",
		},
		{
			name:           "empty request ID",
			requestID:      "",
			expectedOutput: "",
		},
		{
			name:           "UUID format request ID",
			requestID:      "550e8400-e29b-41d4-a716-446655440000",
			expectedOutput: "Snyk-Request-Id: 550e8400-e29b-41d4-a716-446655440000\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock response with the header
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.requestID != "" {
				resp.Header.Set(SnykRequestIDHeader, tt.requestID)
			}

			// Capture stderr
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			printSnykRequestID(resp)

			w.Close()
			os.Stderr = oldStderr

			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			if output != tt.expectedOutput {
				t.Errorf("printSnykRequestID() output = %q, want %q", output, tt.expectedOutput)
			}
		})
	}
}

func TestHandleHTTPResponse_PrintsRequestIDOnError(t *testing.T) {
	tests := []struct {
		name             string
		statusCode       int
		requestID        string
		expectRequestID  bool
		verbose          bool
		silent           bool
		includeResp      bool
		responseBody     string
		expectedInStderr string
		expectedInStdout string
	}{
		{
			name:             "400 error prints request ID",
			statusCode:       400,
			requestID:        "test-request-id-400",
			expectRequestID:  true,
			verbose:          false,
			silent:           false,
			includeResp:      false,
			responseBody:     `{"error":"Bad Request"}`,
			expectedInStderr: "Snyk-Request-Id: test-request-id-400",
			expectedInStdout: `{"error":"Bad Request"}`,
		},
		{
			name:             "401 error prints request ID",
			statusCode:       401,
			requestID:        "test-request-id-401",
			expectRequestID:  true,
			verbose:          false,
			silent:           false,
			includeResp:      false,
			responseBody:     `{"error":"Unauthorized"}`,
			expectedInStderr: "Snyk-Request-Id: test-request-id-401",
			expectedInStdout: `{"error":"Unauthorized"}`,
		},
		{
			name:             "404 error prints request ID",
			statusCode:       404,
			requestID:        "test-request-id-404",
			expectRequestID:  true,
			verbose:          false,
			silent:           false,
			includeResp:      false,
			responseBody:     `{"error":"Not Found"}`,
			expectedInStderr: "Snyk-Request-Id: test-request-id-404",
			expectedInStdout: `{"error":"Not Found"}`,
		},
		{
			name:             "500 error prints request ID",
			statusCode:       500,
			requestID:        "test-request-id-500",
			expectRequestID:  true,
			verbose:          false,
			silent:           false,
			includeResp:      false,
			responseBody:     `{"error":"Internal Server Error"}`,
			expectedInStderr: "Snyk-Request-Id: test-request-id-500",
			expectedInStdout: `{"error":"Internal Server Error"}`,
		},
		{
			name:             "200 success does NOT print request ID",
			statusCode:       200,
			requestID:        "test-request-id-200",
			expectRequestID:  false,
			verbose:          false,
			silent:           false,
			includeResp:      false,
			responseBody:     `{"data":"success"}`,
			expectedInStderr: "",
			expectedInStdout: `{"data":"success"}`,
		},
		{
			name:             "201 created does NOT print request ID",
			statusCode:       201,
			requestID:        "test-request-id-201",
			expectRequestID:  false,
			verbose:          false,
			silent:           false,
			includeResp:      false,
			responseBody:     `{"data":"created"}`,
			expectedInStderr: "",
			expectedInStdout: `{"data":"created"}`,
		},
		{
			name:             "error without request ID header",
			statusCode:       400,
			requestID:        "",
			expectRequestID:  false,
			verbose:          false,
			silent:           false,
			includeResp:      false,
			responseBody:     `{"error":"Bad Request"}`,
			expectedInStderr: "",
			expectedInStdout: `{"error":"Bad Request"}`,
		},
		{
			name:             "error with verbose mode",
			statusCode:       403,
			requestID:        "test-request-id-403",
			expectRequestID:  true,
			verbose:          true,
			silent:           false,
			includeResp:      false,
			responseBody:     `{"error":"Forbidden"}`,
			expectedInStderr: "Snyk-Request-Id: test-request-id-403",
			expectedInStdout: `{"error":"Forbidden"}`,
		},
		{
			name:             "error with silent mode still prints request ID",
			statusCode:       400,
			requestID:        "test-request-id-silent",
			expectRequestID:  true,
			verbose:          false,
			silent:           true,
			includeResp:      false,
			responseBody:     `{"error":"Bad Request"}`,
			expectedInStderr: "Snyk-Request-Id: test-request-id-silent",
			expectedInStdout: "", // silent mode suppresses body
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock response
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Status:     http.StatusText(tt.statusCode),
				Proto:      "HTTP/1.1",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(tt.responseBody)),
			}
			if tt.requestID != "" {
				resp.Header.Set(SnykRequestIDHeader, tt.requestID)
			}

			// Capture stderr
			oldStderr := os.Stderr
			rErr, wErr, _ := os.Pipe()
			os.Stderr = wErr

			// Capture stdout
			oldStdout := os.Stdout
			rOut, wOut, _ := os.Pipe()
			os.Stdout = wOut

			// Call the function
			_ = HandleHTTPResponse(resp, tt.includeResp, tt.verbose, tt.silent)

			// Restore and read outputs
			wErr.Close()
			wOut.Close()
			os.Stderr = oldStderr
			os.Stdout = oldStdout

			var bufErr, bufOut bytes.Buffer
			io.Copy(&bufErr, rErr)
			io.Copy(&bufOut, rOut)
			stderrOutput := bufErr.String()
			stdoutOutput := bufOut.String()

			// Check stderr for request ID
			if tt.expectRequestID {
				if !strings.Contains(stderrOutput, tt.expectedInStderr) {
					t.Errorf("Expected stderr to contain %q, got %q", tt.expectedInStderr, stderrOutput)
				}
			} else {
				if strings.Contains(stderrOutput, "Snyk-Request-Id:") {
					t.Errorf("Expected stderr NOT to contain Snyk-Request-Id, got %q", stderrOutput)
				}
			}

			// Check stdout for response body
			if tt.expectedInStdout != "" {
				if !strings.Contains(stdoutOutput, tt.expectedInStdout) {
					t.Errorf("Expected stdout to contain %q, got %q", tt.expectedInStdout, stdoutOutput)
				}
			}
		})
	}
}

func TestHandleHTTPResponse_Integration(t *testing.T) {
	// Create a test server that returns errors with snyk-request-id
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set the Snyk-Request-Id header
		w.Header().Set(SnykRequestIDHeader, "integration-test-request-id")

		if strings.Contains(r.URL.Path, "/error") {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"Bad Request","message":"Test error"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"success"}`))
	}))
	defer server.Close()

	t.Run("error response includes request ID in stderr", func(t *testing.T) {
		// Make request to error endpoint
		resp, err := http.Get(server.URL + "/error")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Capture stderr
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		// Capture stdout
		oldStdout := os.Stdout
		rOut, wOut, _ := os.Pipe()
		os.Stdout = wOut

		_ = HandleHTTPResponse(resp, false, false, false)

		w.Close()
		wOut.Close()
		os.Stderr = oldStderr
		os.Stdout = oldStdout

		var buf bytes.Buffer
		io.Copy(&buf, r)
		stderrOutput := buf.String()

		// Drain stdout
		io.Copy(io.Discard, rOut)

		if !strings.Contains(stderrOutput, "integration-test-request-id") {
			t.Errorf("Expected request ID in stderr, got: %q", stderrOutput)
		}
	})

	t.Run("success response does not print request ID", func(t *testing.T) {
		// Make request to success endpoint
		resp, err := http.Get(server.URL + "/success")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		// Capture stderr
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		// Capture stdout
		oldStdout := os.Stdout
		rOut, wOut, _ := os.Pipe()
		os.Stdout = wOut

		_ = HandleHTTPResponse(resp, false, false, false)

		w.Close()
		wOut.Close()
		os.Stderr = oldStderr
		os.Stdout = oldStdout

		var buf bytes.Buffer
		io.Copy(&buf, r)
		stderrOutput := buf.String()

		// Drain stdout
		io.Copy(io.Discard, rOut)

		if strings.Contains(stderrOutput, "Snyk-Request-Id") {
			t.Errorf("Did not expect request ID in stderr for success response, got: %q", stderrOutput)
		}
	})
}
