package cmd

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseSnykToken(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    SnykToken
		expectError bool
	}{
		{
			name: "Valid token JSON",
			input: `{
				"access_token": "access_123",
				"refresh_token": "refresh_456",
				"expiry": "2024-12-31T23:59:59Z"
			}`,
			expected: SnykToken{
				AccessToken:  "access_123",
				RefreshToken: "refresh_456",
				Expiry:       time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
			},
			expectError: false,
		},
		{
			name:        "Invalid JSON",
			input:       `{"invalid": json}`,
			expected:    SnykToken{},
			expectError: true,
		},
		{
			name:        "Empty JSON",
			input:       `{}`,
			expected:    SnykToken{},
			expectError: false,
		},
		{
			name: "Missing fields",
			input: `{
				"access_token": "access_123"
			}`,
			expected: SnykToken{
				AccessToken: "access_123",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseSnykToken(tt.input)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectError {
				if result.AccessToken != tt.expected.AccessToken {
					t.Errorf("AccessToken = %v, want %v", result.AccessToken, tt.expected.AccessToken)
				}
				if result.RefreshToken != tt.expected.RefreshToken {
					t.Errorf("RefreshToken = %v, want %v", result.RefreshToken, tt.expected.RefreshToken)
				}
				if !result.Expiry.Equal(tt.expected.Expiry) {
					t.Errorf("Expiry = %v, want %v", result.Expiry, tt.expected.Expiry)
				}
			}
		})
	}
}

func TestIsTokenExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		token    SnykToken
		expected bool
	}{
		{
			name: "Token not expired",
			token: SnykToken{
				Expiry: now.Add(1 * time.Hour),
			},
			expected: false,
		},
		{
			name: "Token expired",
			token: SnykToken{
				Expiry: now.Add(-1 * time.Hour),
			},
			expected: true,
		},
		{
			name: "Token expires soon (within 5 minutes)",
			token: SnykToken{
				Expiry: now.Add(2 * time.Minute),
			},
			expected: true, // Should refresh if expires within 5 minutes
		},
		{
			name: "Token expires in exactly 5 minutes",
			token: SnykToken{
				Expiry: now.Add(5 * time.Minute),
			},
			expected: true,
		},
		{
			name: "Token expires in 6 minutes",
			token: SnykToken{
				Expiry: now.Add(6 * time.Minute),
			},
			expected: false,
		},
		{
			name: "Zero expiry time",
			token: SnykToken{
				Expiry: time.Time{},
			},
			expected: true, // Zero time should be considered expired
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTokenExpired(tt.token)
			if result != tt.expected {
				t.Errorf("isTokenExpired() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestBuildAuthHeader(t *testing.T) {
	tests := []struct {
		name        string
		token       SnykToken
		expected    string
		expectError bool
	}{
		{
			name: "Valid access token",
			token: SnykToken{
				AccessToken: "access_123",
			},
			expected:    "Bearer access_123",
			expectError: false,
		},
		{
			name: "Empty access token",
			token: SnykToken{
				AccessToken: "",
			},
			expected:    "",
			expectError: true,
		},
		{
			name: "Token with spaces",
			token: SnykToken{
				AccessToken: "  access_123  ",
			},
			expected:    "Bearer access_123",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildAuthHeaderFromToken(tt.token)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("buildAuthHeader() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTokenPrecedence(t *testing.T) {
	// Test that manual Authorization header takes precedence over automatic token
	tests := []struct {
		name           string
		manualHeaders  []string
		autoToken      string
		expectedHeader string
		shouldUseAuto  bool
	}{
		{
			name:           "Manual auth header takes precedence",
			manualHeaders:  []string{"Authorization: Bearer manual_token"},
			autoToken:      "auto_token",
			expectedHeader: "Bearer manual_token",
			shouldUseAuto:  false,
		},
		{
			name:           "Manual auth header with different case",
			manualHeaders:  []string{"authorization: Bearer manual_token"},
			autoToken:      "auto_token",
			expectedHeader: "Bearer manual_token",
			shouldUseAuto:  false,
		},
		{
			name:           "No manual auth header, use auto",
			manualHeaders:  []string{"Content-Type: application/json"},
			autoToken:      "auto_token",
			expectedHeader: "Bearer auto_token",
			shouldUseAuto:  true,
		},
		{
			name:           "Empty manual headers, use auto",
			manualHeaders:  []string{},
			autoToken:      "auto_token",
			expectedHeader: "Bearer auto_token",
			shouldUseAuto:  true,
		},
		{
			name:           "Multiple headers, one is auth",
			manualHeaders:  []string{"Content-Type: application/json", "Authorization: Bearer manual_token", "X-Custom: value"},
			autoToken:      "auto_token",
			expectedHeader: "Bearer manual_token",
			shouldUseAuto:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldUse, authHeader := shouldUseAutoAuth(tt.manualHeaders, tt.autoToken)

			if shouldUse != tt.shouldUseAuto {
				t.Errorf("shouldUseAutoAuth() shouldUse = %v, want %v", shouldUse, tt.shouldUseAuto)
			}

			if authHeader != tt.expectedHeader {
				t.Errorf("shouldUseAutoAuth() authHeader = %v, want %v", authHeader, tt.expectedHeader)
			}
		})
	}
}

func TestSnykTokenSerialization(t *testing.T) {
	// Test that we can serialize token back to JSON for saving
	token := SnykToken{
		AccessToken:  "new_access_token",
		RefreshToken: "refresh_token",
		Expiry:       time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	jsonData, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("Failed to marshal token: %v", err)
	}

	var parsedToken SnykToken
	err = json.Unmarshal(jsonData, &parsedToken)
	if err != nil {
		t.Fatalf("Failed to unmarshal token: %v", err)
	}

	if parsedToken.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %v, want %v", parsedToken.AccessToken, token.AccessToken)
	}
	if parsedToken.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken = %v, want %v", parsedToken.RefreshToken, token.RefreshToken)
	}
	if !parsedToken.Expiry.Equal(token.Expiry) {
		t.Errorf("Expiry = %v, want %v", parsedToken.Expiry, token.Expiry)
	}
}

// Mock functions to test command execution behavior
func TestMockSnykCommand(t *testing.T) {
	tests := []struct {
		name           string
		command        []string
		mockOutput     string
		mockError      error
		expectedResult string
		expectError    bool
	}{
		{
			name:           "Successful snyk config get",
			command:        []string{"snyk", "config", "get", "INTERNAL_OAUTH_TOKEN_STORAGE"},
			mockOutput:     `{"access_token":"test_token","refresh_token":"refresh_test","expiry":"2024-12-31T23:59:59Z"}`,
			mockError:      nil,
			expectedResult: `{"access_token":"test_token","refresh_token":"refresh_test","expiry":"2024-12-31T23:59:59Z"}`,
			expectError:    false,
		},
		{
			name:           "Snyk command not found",
			command:        []string{"snyk", "config", "get", "INTERNAL_OAUTH_TOKEN_STORAGE"},
			mockOutput:     "",
			mockError:      &mockError{msg: "executable file not found"},
			expectedResult: "",
			expectError:    true,
		},
		{
			name:           "Snyk config empty",
			command:        []string{"snyk", "config", "get", "INTERNAL_OAUTH_TOKEN_STORAGE"},
			mockOutput:     "",
			mockError:      nil,
			expectedResult: "",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This would be implemented with actual command execution logic
			result, err := mockExecuteCommand(tt.command, tt.mockOutput, tt.mockError)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result != tt.expectedResult {
				t.Errorf("executeCommand() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

// Helper types for testing
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

// Mock function for testing command execution
func mockExecuteCommand(command []string, mockOutput string, mockError error) (string, error) {
	if mockError != nil {
		return "", mockError
	}
	return mockOutput, nil
}

func TestAuthenticationPrecedence(t *testing.T) {
	// Test the full authentication precedence: Authorization header > client_credentials > SNYK_TOKEN > OAuth
	tests := []struct {
		name           string
		manualHeaders  []string
		clientID       string
		clientSecret   string
		snykTokenEnv   string
		oauthToken     string
		expectedSource string // "manual", "client_credentials", "env", "oauth", "none"
		expectedToken  string
		shouldUseAuth  bool
	}{
		{
			name:           "Manual auth header takes highest precedence",
			manualHeaders:  []string{"Authorization: Bearer manual_token"},
			clientID:       "",
			clientSecret:   "",
			snykTokenEnv:   "env_token",
			oauthToken:     "oauth_token",
			expectedSource: "manual",
			expectedToken:  "Bearer manual_token",
			shouldUseAuth:  false, // Manual header, so don't use auto auth
		},
		{
			name:           "SNYK_TOKEN used when no manual header or client credentials",
			manualHeaders:  []string{"Content-Type: application/json"},
			clientID:       "",
			clientSecret:   "",
			snykTokenEnv:   "env_token",
			oauthToken:     "oauth_token",
			expectedSource: "env",
			expectedToken:  "Bearer env_token",
			shouldUseAuth:  true,
		},
		{
			name:           "OAuth used when no manual header, client credentials, or SNYK_TOKEN",
			manualHeaders:  []string{"Content-Type: application/json"},
			clientID:       "",
			clientSecret:   "",
			snykTokenEnv:   "",
			oauthToken:     "oauth_token",
			expectedSource: "oauth",
			expectedToken:  "Bearer oauth_token",
			shouldUseAuth:  true,
		},
		{
			name:           "No auth when none available",
			manualHeaders:  []string{"Content-Type: application/json"},
			clientID:       "",
			clientSecret:   "",
			snykTokenEnv:   "",
			oauthToken:     "",
			expectedSource: "none",
			expectedToken:  "",
			shouldUseAuth:  false,
		},
		{
			name:           "SNYK_TOKEN overrides OAuth even when OAuth available",
			manualHeaders:  []string{},
			clientID:       "",
			clientSecret:   "",
			snykTokenEnv:   "env_token",
			oauthToken:     "oauth_token",
			expectedSource: "env",
			expectedToken:  "Bearer env_token",
			shouldUseAuth:  true,
		},
		{
			name:           "Empty SNYK_TOKEN falls back to OAuth",
			manualHeaders:  []string{},
			clientID:       "",
			clientSecret:   "",
			snykTokenEnv:   "   ", // Whitespace should be treated as empty
			oauthToken:     "oauth_token",
			expectedSource: "oauth",
			expectedToken:  "Bearer oauth_token",
			shouldUseAuth:  true,
		},
		{
			name:           "Case insensitive manual auth header still wins",
			manualHeaders:  []string{"authorization: Bearer manual_token"},
			clientID:       "",
			clientSecret:   "",
			snykTokenEnv:   "env_token",
			oauthToken:     "oauth_token",
			expectedSource: "manual",
			expectedToken:  "Bearer manual_token",
			shouldUseAuth:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldUse, authHeader, source := determineAuthMethod(tt.manualHeaders, tt.clientID, tt.clientSecret, tt.snykTokenEnv, tt.oauthToken)

			if shouldUse != tt.shouldUseAuth {
				t.Errorf("determineAuthMethod() shouldUse = %v, want %v", shouldUse, tt.shouldUseAuth)
			}

			if authHeader != tt.expectedToken {
				t.Errorf("determineAuthMethod() authHeader = %v, want %v", authHeader, tt.expectedToken)
			}

			if source != tt.expectedSource {
				t.Errorf("determineAuthMethod() source = %v, want %v", source, tt.expectedSource)
			}
		})
	}
}

func TestSnykTokenValidation(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		expected    string
		expectError bool
	}{
		{
			name:        "Valid SNYK_TOKEN",
			envValue:    "snyk_token_12345",
			expected:    "Bearer snyk_token_12345",
			expectError: false,
		},
		{
			name:        "SNYK_TOKEN with whitespace",
			envValue:    "  snyk_token_12345  ",
			expected:    "Bearer snyk_token_12345",
			expectError: false,
		},
		{
			name:        "Empty SNYK_TOKEN",
			envValue:    "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "Whitespace only SNYK_TOKEN",
			envValue:    "   ",
			expected:    "",
			expectError: true,
		},
		{
			name:        "SNYK_TOKEN with special characters",
			envValue:    "snyk_token-with.special_chars123",
			expected:    "Bearer snyk_token-with.special_chars123",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildAuthHeaderFromEnvToken(tt.envValue)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("buildAuthHeaderFromEnvToken() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetAuthSourcePriority(t *testing.T) {
	// Test the priority logic in isolation
	// Priority order: manual > client_credentials > env (SNYK_TOKEN) > oauth
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
			name:            "Manual auth blocks all automatic auth",
			hasManualAuth:   true,
			clientID:        "client_id",
			clientSecret:    "client_secret",
			snykToken:       "env_token",
			oauthToken:      "oauth_token",
			expectedSource:  "manual",
			expectedUseAuto: false,
		},
		{
			name:            "Client credentials used when no manual auth",
			hasManualAuth:   false,
			clientID:        "client_id",
			clientSecret:    "client_secret",
			snykToken:       "env_token",
			oauthToken:      "oauth_token",
			expectedSource:  "client_credentials",
			expectedUseAuto: true,
		},
		{
			name:            "SNYK_TOKEN used when no manual auth or client credentials",
			hasManualAuth:   false,
			clientID:        "",
			clientSecret:    "",
			snykToken:       "env_token",
			oauthToken:      "oauth_token",
			expectedSource:  "env",
			expectedUseAuto: true,
		},
		{
			name:            "OAuth used when no manual auth, client credentials, or SNYK_TOKEN",
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
			name:            "Incomplete client credentials (missing secret) falls through",
			hasManualAuth:   false,
			clientID:        "client_id",
			clientSecret:    "",
			snykToken:       "env_token",
			oauthToken:      "",
			expectedSource:  "env",
			expectedUseAuto: true,
		},
		{
			name:            "Incomplete client credentials (missing id) falls through",
			hasManualAuth:   false,
			clientID:        "",
			clientSecret:    "client_secret",
			snykToken:       "env_token",
			oauthToken:      "",
			expectedSource:  "env",
			expectedUseAuto: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, useAuto := getAuthSourcePriority(tt.hasManualAuth, tt.clientID, tt.clientSecret, tt.snykToken, tt.oauthToken)

			if source != tt.expectedSource {
				t.Errorf("getAuthSourcePriority() source = %v, want %v", source, tt.expectedSource)
			}

			if useAuto != tt.expectedUseAuto {
				t.Errorf("getAuthSourcePriority() useAuto = %v, want %v", useAuto, tt.expectedUseAuto)
			}
		})
	}
}
