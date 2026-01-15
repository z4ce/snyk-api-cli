package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsOAuth2TokenExpired(t *testing.T) {
	tests := []struct {
		name     string
		token    *OAuth2Token
		expected bool
	}{
		{
			name:     "Nil token is expired",
			token:    nil,
			expected: true,
		},
		{
			name: "Empty access token is expired",
			token: &OAuth2Token{
				AccessToken: "",
			},
			expected: true,
		},
		{
			name: "Token with zero expiry is not expired",
			token: &OAuth2Token{
				AccessToken: "test_token",
				expiresAt:   time.Time{},
			},
			expected: false,
		},
		{
			name: "Token expiring soon is expired",
			token: &OAuth2Token{
				AccessToken: "test_token",
				expiresAt:   time.Now().Add(2 * time.Minute),
			},
			expected: true, // Within 5-minute buffer
		},
		{
			name: "Token not expiring soon is valid",
			token: &OAuth2Token{
				AccessToken: "test_token",
				expiresAt:   time.Now().Add(10 * time.Minute),
			},
			expected: false,
		},
		{
			name: "Already expired token",
			token: &OAuth2Token{
				AccessToken: "test_token",
				expiresAt:   time.Now().Add(-1 * time.Hour),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isOAuth2TokenExpired(tt.token)
			if result != tt.expected {
				t.Errorf("isOAuth2TokenExpired() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestBuildTokenURLFromEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		expected string
	}{
		{
			name:     "Simple endpoint",
			endpoint: "api.snyk.io",
			expected: "https://api.snyk.io/oauth2/token",
		},
		{
			name:     "Endpoint with https prefix",
			endpoint: "https://api.snyk.io",
			expected: "https://api.snyk.io/oauth2/token",
		},
		{
			name:     "Endpoint with http prefix",
			endpoint: "http://api.snyk.io",
			expected: "https://api.snyk.io/oauth2/token",
		},
		{
			name:     "Endpoint with trailing slash",
			endpoint: "api.snyk.io/",
			expected: "https://api.snyk.io/oauth2/token",
		},
		{
			name:     "EU endpoint",
			endpoint: "api.eu.snyk.io",
			expected: "https://api.eu.snyk.io/oauth2/token",
		},
		{
			name:     "Custom endpoint",
			endpoint: "custom.snyk.endpoint.com",
			expected: "https://custom.snyk.endpoint.com/oauth2/token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildTokenURLFromEndpoint(tt.endpoint)
			if result != tt.expected {
				t.Errorf("buildTokenURLFromEndpoint(%q) = %q, want %q", tt.endpoint, result, tt.expected)
			}
		})
	}
}

func TestFetchClientCredentialsToken(t *testing.T) {
	// Test successful token fetch
	t.Run("Successful token fetch", func(t *testing.T) {
		tokenResponse := OAuth2Token{
			AccessToken: "test_access_token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "read write",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request method
			if r.Method != "POST" {
				t.Errorf("Expected POST request, got %s", r.Method)
			}

			// Verify content type
			if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
				t.Errorf("Expected Content-Type application/x-www-form-urlencoded, got %s", ct)
			}

			// Verify basic auth
			username, password, ok := r.BasicAuth()
			if !ok {
				t.Error("Expected Basic Auth header")
			}
			if username != "test_client_id" || password != "test_client_secret" {
				t.Errorf("Unexpected credentials: %s:%s", username, password)
			}

			// Verify grant type
			if err := r.ParseForm(); err != nil {
				t.Errorf("Failed to parse form: %v", err)
			}
			if gt := r.FormValue("grant_type"); gt != "client_credentials" {
				t.Errorf("Expected grant_type=client_credentials, got %s", gt)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tokenResponse)
		}))
		defer server.Close()

		config := ClientCredentialsConfig{
			ClientID:     "test_client_id",
			ClientSecret: "test_client_secret",
			TokenURL:     server.URL,
		}

		token, err := fetchClientCredentialsToken(config)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if token.AccessToken != "test_access_token" {
			t.Errorf("AccessToken = %q, want %q", token.AccessToken, "test_access_token")
		}
		if token.TokenType != "Bearer" {
			t.Errorf("TokenType = %q, want %q", token.TokenType, "Bearer")
		}
		if token.ExpiresIn != 3600 {
			t.Errorf("ExpiresIn = %d, want %d", token.ExpiresIn, 3600)
		}
		if token.expiresAt.IsZero() {
			t.Error("Expected expiresAt to be set")
		}
	})

	// Test failed token fetch (HTTP error)
	t.Run("Failed token fetch - HTTP error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_client","error_description":"Invalid credentials"}`))
		}))
		defer server.Close()

		config := ClientCredentialsConfig{
			ClientID:     "bad_client_id",
			ClientSecret: "bad_client_secret",
			TokenURL:     server.URL,
		}

		_, err := fetchClientCredentialsToken(config)
		if err == nil {
			t.Error("Expected error, got nil")
		}
	})

	// Test failed token fetch (invalid JSON)
	t.Run("Failed token fetch - invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{invalid json}`))
		}))
		defer server.Close()

		config := ClientCredentialsConfig{
			ClientID:     "test_client_id",
			ClientSecret: "test_client_secret",
			TokenURL:     server.URL,
		}

		_, err := fetchClientCredentialsToken(config)
		if err == nil {
			t.Error("Expected error, got nil")
		}
	})
}

func TestGetClientCredentialsToken(t *testing.T) {
	// Clear any cached token before testing
	clearCachedClientCredentialsToken()

	t.Run("Empty credentials returns error", func(t *testing.T) {
		config := ClientCredentialsConfig{
			ClientID:     "",
			ClientSecret: "",
		}

		_, err := getClientCredentialsToken(config)
		if err == nil {
			t.Error("Expected error for empty credentials")
		}
	})

	t.Run("Token caching works", func(t *testing.T) {
		clearCachedClientCredentialsToken()

		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			tokenResponse := OAuth2Token{
				AccessToken: "cached_token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tokenResponse)
		}))
		defer server.Close()

		config := ClientCredentialsConfig{
			ClientID:     "test_client_id",
			ClientSecret: "test_client_secret",
			TokenURL:     server.URL,
		}

		// First call should fetch token
		token1, err := getClientCredentialsToken(config)
		if err != nil {
			t.Fatalf("Unexpected error on first call: %v", err)
		}

		// Second call should use cached token
		token2, err := getClientCredentialsToken(config)
		if err != nil {
			t.Fatalf("Unexpected error on second call: %v", err)
		}

		if token1 != token2 {
			t.Errorf("Expected same token, got %q and %q", token1, token2)
		}

		// Should have only made one HTTP request
		if callCount != 1 {
			t.Errorf("Expected 1 HTTP request, got %d", callCount)
		}

		clearCachedClientCredentialsToken()
	})
}

func TestGetAuthSourcePriorityWithClientCredentials(t *testing.T) {
	tests := []struct {
		name            string
		hasManualAuth   bool
		clientID        string
		clientSecret    string
		snykToken       string
		oauthToken      string
		expectedSource  string
		expectedUseAuto bool
	}{
		{
			name:            "Manual auth takes highest precedence",
			hasManualAuth:   true,
			clientID:        "client_id",
			clientSecret:    "client_secret",
			snykToken:       "snyk_token",
			oauthToken:      "oauth_token",
			expectedSource:  "manual",
			expectedUseAuto: false,
		},
		{
			name:            "Client credentials takes second precedence",
			hasManualAuth:   false,
			clientID:        "client_id",
			clientSecret:    "client_secret",
			snykToken:       "snyk_token",
			oauthToken:      "oauth_token",
			expectedSource:  "client_credentials",
			expectedUseAuto: true,
		},
		{
			name:            "SNYK_TOKEN used when no client credentials",
			hasManualAuth:   false,
			clientID:        "",
			clientSecret:    "",
			snykToken:       "snyk_token",
			oauthToken:      "oauth_token",
			expectedSource:  "env",
			expectedUseAuto: true,
		},
		{
			name:            "OAuth used when no other options",
			hasManualAuth:   false,
			clientID:        "",
			clientSecret:    "",
			snykToken:       "",
			oauthToken:      "oauth_token",
			expectedSource:  "oauth",
			expectedUseAuto: true,
		},
		{
			name:            "No auth when nothing available",
			hasManualAuth:   false,
			clientID:        "",
			clientSecret:    "",
			snykToken:       "",
			oauthToken:      "",
			expectedSource:  "none",
			expectedUseAuto: false,
		},
		{
			name:            "Client ID without secret falls through to SNYK_TOKEN",
			hasManualAuth:   false,
			clientID:        "client_id",
			clientSecret:    "",
			snykToken:       "snyk_token",
			oauthToken:      "",
			expectedSource:  "env",
			expectedUseAuto: true,
		},
		{
			name:            "Client secret without ID falls through to SNYK_TOKEN",
			hasManualAuth:   false,
			clientID:        "",
			clientSecret:    "client_secret",
			snykToken:       "snyk_token",
			oauthToken:      "",
			expectedSource:  "env",
			expectedUseAuto: true,
		},
		{
			name:            "Whitespace-only client credentials fall through",
			hasManualAuth:   false,
			clientID:        "   ",
			clientSecret:    "   ",
			snykToken:       "snyk_token",
			oauthToken:      "",
			expectedSource:  "env",
			expectedUseAuto: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, useAuto := getAuthSourcePriority(tt.hasManualAuth, tt.clientID, tt.clientSecret, tt.snykToken, tt.oauthToken)

			if source != tt.expectedSource {
				t.Errorf("getAuthSourcePriority() source = %q, want %q", source, tt.expectedSource)
			}

			if useAuto != tt.expectedUseAuto {
				t.Errorf("getAuthSourcePriority() useAuto = %v, want %v", useAuto, tt.expectedUseAuto)
			}
		})
	}
}

