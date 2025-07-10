package cmd

import (
	"net/http"
	"strings"
	"testing"
)

func TestBuildURL(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		path     string
		version  string
		expected string
	}{
		{
			name:     "REST endpoint with default version",
			endpoint: "api.snyk.io",
			path:     "/rest/orgs",
			version:  "2024-10-15",
			expected: "https://api.snyk.io/rest/orgs?version=2024-10-15",
		},
		{
			name:     "REST endpoint with custom version",
			endpoint: "api.snyk.io",
			path:     "/rest/orgs/123/projects",
			version:  "2023-05-01",
			expected: "https://api.snyk.io/rest/orgs/123/projects?version=2023-05-01",
		},
		{
			name:     "Non-REST endpoint (no version parameter)",
			endpoint: "api.snyk.io",
			path:     "/v1/user",
			version:  "2024-10-15",
			expected: "https://api.snyk.io/v1/user",
		},
		{
			name:     "Non-REST endpoint with path parameters",
			endpoint: "api.snyk.io",
			path:     "/v1/orgs/123/projects",
			version:  "2024-10-15",
			expected: "https://api.snyk.io/v1/orgs/123/projects",
		},
		{
			name:     "Path without leading slash",
			endpoint: "api.snyk.io",
			path:     "rest/orgs",
			version:  "2024-10-15",
			expected: "https://api.snyk.io/rest/orgs?version=2024-10-15",
		},
		{
			name:     "Custom endpoint",
			endpoint: "api.eu.snyk.io",
			path:     "/rest/orgs",
			version:  "2024-10-15",
			expected: "https://api.eu.snyk.io/rest/orgs?version=2024-10-15",
		},
		{
			name:     "Path with existing query parameters",
			endpoint: "api.snyk.io",
			path:     "/rest/orgs?limit=10",
			version:  "2024-10-15",
			expected: "https://api.snyk.io/rest/orgs?limit=10&version=2024-10-15",
		},
		{
			name:     "Non-REST path with existing query parameters",
			endpoint: "api.snyk.io",
			path:     "/v1/orgs?limit=10",
			version:  "2024-10-15",
			expected: "https://api.snyk.io/v1/orgs?limit=10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildURL(tt.endpoint, tt.path, tt.version)
			if err != nil {
				t.Fatalf("buildURL() error = %v", err)
			}
			if result != tt.expected {
				t.Errorf("buildURL() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCreateRequest(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		url            string
		data           string
		expectedMethod string
		expectedURL    string
		expectBody     bool
		expectedCT     string
	}{
		{
			name:           "GET request without data",
			method:         "GET",
			url:            "https://api.snyk.io/rest/orgs",
			data:           "",
			expectedMethod: "GET",
			expectedURL:    "https://api.snyk.io/rest/orgs",
			expectBody:     false,
			expectedCT:     "",
		},
		{
			name:           "POST request with JSON data",
			method:         "POST",
			url:            "https://api.snyk.io/rest/orgs",
			data:           `{"name":"test"}`,
			expectedMethod: "POST",
			expectedURL:    "https://api.snyk.io/rest/orgs",
			expectBody:     true,
			expectedCT:     "application/json",
		},
		{
			name:           "PUT request with data",
			method:         "PUT",
			url:            "https://api.snyk.io/rest/orgs/123",
			data:           `{"name":"updated"}`,
			expectedMethod: "PUT",
			expectedURL:    "https://api.snyk.io/rest/orgs/123",
			expectBody:     true,
			expectedCT:     "application/json",
		},
		{
			name:           "DELETE request without data",
			method:         "DELETE",
			url:            "https://api.snyk.io/rest/orgs/123",
			data:           "",
			expectedMethod: "DELETE",
			expectedURL:    "https://api.snyk.io/rest/orgs/123",
			expectBody:     false,
			expectedCT:     "",
		},
		{
			name:           "PATCH request with data",
			method:         "PATCH",
			url:            "https://api.snyk.io/rest/orgs/123",
			data:           `{"name":"patched"}`,
			expectedMethod: "PATCH",
			expectedURL:    "https://api.snyk.io/rest/orgs/123",
			expectBody:     true,
			expectedCT:     "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := createRequest(tt.method, tt.url, tt.data)
			if err != nil {
				t.Fatalf("createRequest() error = %v", err)
			}

			if req.Method != tt.expectedMethod {
				t.Errorf("createRequest() method = %v, want %v", req.Method, tt.expectedMethod)
			}

			if req.URL.String() != tt.expectedURL {
				t.Errorf("createRequest() URL = %v, want %v", req.URL.String(), tt.expectedURL)
			}

			if tt.expectBody {
				if req.Body == nil {
					t.Error("createRequest() expected body but got nil")
				}
			} else {
				if req.Body != nil {
					t.Error("createRequest() expected no body but got one")
				}
			}

			contentType := req.Header.Get("Content-Type")
			if contentType != tt.expectedCT {
				t.Errorf("createRequest() Content-Type = %v, want %v", contentType, tt.expectedCT)
			}
		})
	}
}

func TestAddHeaders(t *testing.T) {
	tests := []struct {
		name        string
		headers     []string
		userAgent   string
		expectError bool
		expected    map[string]string
	}{
		{
			name:        "Valid headers",
			headers:     []string{"Authorization: Bearer token123", "Content-Type: application/json"},
			userAgent:   "test-agent/1.0",
			expectError: false,
			expected: map[string]string{
				"Authorization": "Bearer token123",
				"Content-Type":  "application/json",
				"User-Agent":    "test-agent/1.0",
			},
		},
		{
			name:        "Headers with spaces",
			headers:     []string{"X-Custom-Header:   value with spaces   ", "Another-Header:value"},
			userAgent:   "test-agent/1.0",
			expectError: false,
			expected: map[string]string{
				"X-Custom-Header": "value with spaces",
				"Another-Header":  "value",
				"User-Agent":      "test-agent/1.0",
			},
		},
		{
			name:        "Only user agent",
			headers:     []string{},
			userAgent:   "snyk-api-cli/1.0",
			expectError: false,
			expected: map[string]string{
				"User-Agent": "snyk-api-cli/1.0",
			},
		},
		{
			name:        "Invalid header format - no colon",
			headers:     []string{"InvalidHeader"},
			userAgent:   "test-agent/1.0",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Invalid header format - multiple values",
			headers:     []string{"Authorization: Bearer token123", "Invalid Header No Colon"},
			userAgent:   "test-agent/1.0",
			expectError: true,
			expected:    nil,
		},
		{
			name:        "Header with colon in value",
			headers:     []string{"X-Time: 2024-01-01T10:30:00Z"},
			userAgent:   "test-agent/1.0",
			expectError: false,
			expected: map[string]string{
				"X-Time":     "2024-01-01T10:30:00Z",
				"User-Agent": "test-agent/1.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com", nil)
			err := addHeaders(req, tt.headers, tt.userAgent)

			if tt.expectError {
				if err == nil {
					t.Error("addHeaders() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("addHeaders() unexpected error = %v", err)
			}

			for key, expectedValue := range tt.expected {
				actualValue := req.Header.Get(key)
				if actualValue != expectedValue {
					t.Errorf("addHeaders() header %s = %v, want %v", key, actualValue, expectedValue)
				}
			}
		})
	}
}

func TestBuildURLEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		path        string
		version     string
		expectError bool
	}{
		{
			name:        "Empty endpoint",
			endpoint:    "",
			path:        "/rest/orgs",
			version:     "2024-10-15",
			expectError: false, // Should still work, just create invalid URL
		},
		{
			name:        "Empty path",
			endpoint:    "api.snyk.io",
			path:        "",
			version:     "2024-10-15",
			expectError: false,
		},
		{
			name:        "Path with special characters",
			endpoint:    "api.snyk.io",
			path:        "/rest/orgs/org%20with%20spaces",
			version:     "2024-10-15",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildURL(tt.endpoint, tt.path, tt.version)
			if tt.expectError && err == nil {
				t.Error("buildURL() expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("buildURL() unexpected error = %v", err)
			}
		})
	}
}

// Test helper function to verify REST path detection
func TestIsRESTPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/rest/orgs", true},
		{"/rest/orgs/123", true},
		{"/rest", true},
		{"/v1/user", false},
		{"/v1/orgs", false},
		{"/api/v1/rest", false}, // rest is not at the beginning
		{"rest/orgs", true},     // without leading slash
		{"/restful/api", false}, // "restful" is not "rest"
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			// Test the logic indirectly through buildURL
			url, err := buildURL("api.snyk.io", tt.path, "2024-10-15")
			if err != nil {
				t.Fatalf("buildURL() error = %v", err)
			}

			hasVersionParam := strings.Contains(url, "version=2024-10-15")
			if hasVersionParam != tt.expected {
				t.Errorf("Path %s: expected version parameter = %v, got %v", tt.path, tt.expected, hasVersionParam)
			}
		})
	}
}
