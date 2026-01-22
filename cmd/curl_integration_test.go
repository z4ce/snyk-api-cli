package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// MockServer creates a test HTTP server that returns predictable responses
func createMockServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return different responses based on the request
		response := map[string]interface{}{
			"method":  r.Method,
			"path":    r.URL.Path,
			"query":   r.URL.RawQuery,
			"headers": r.Header,
		}

		// Read body if present
		if r.Body != nil {
			buf := new(bytes.Buffer)
			buf.ReadFrom(r.Body)
			if buf.Len() > 0 {
				response["body"] = buf.String()
			}
		}

		// Set response based on path
		if strings.Contains(r.URL.Path, "/error") {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error":"Bad Request","status":400}`)
			return
		}

		if strings.Contains(r.URL.Path, "/auth") {
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, `{"error":"Unauthorized","status":401}`)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"success":true,"data":%q}`, fmt.Sprintf("%+v", response))
	}))
}

// Helper function to modify buildURL for testing to use HTTP instead of HTTPS
func buildTestURL(endpoint, path, version string) (string, error) {
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Build base URL with HTTP for testing
	baseURL := fmt.Sprintf("http://%s", endpoint)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL + path)
	if err != nil {
		return "", err
	}

	// Add version parameter if path starts with /rest/ or is exactly /rest
	if path == "/rest" || strings.HasPrefix(path, "/rest/") {
		q := u.Query()
		q.Set("version", version)
		u.RawQuery = q.Encode()
	}

	return u.String(), nil
}

// Modified runCurl for testing that uses HTTP instead of HTTPS
func runCurlTest(cmd *cobra.Command, args []string) error {
	path := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the full URL (using HTTP for testing)
	fullURL, err := buildTestURL(endpoint, path, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "* Requesting %s %s\n", method, fullURL)
	}

	// Create the HTTP request
	req, err := createRequest(method, fullURL, data)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	err = addHeaders(req, headers, userAgent)
	if err != nil {
		return fmt.Errorf("failed to add headers: %w", err)
	}

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response
	return handleResponse(resp, includeResp, verbose, silent)
}

func TestCurlCommandIntegration(t *testing.T) {
	// Create a mock server
	server := createMockServer()
	defer server.Close()

	// Extract host from server URL (remove http://)
	serverHost := strings.TrimPrefix(server.URL, "http://")

	tests := []struct {
		name           string
		args           []string
		globalFlags    map[string]string
		path           string
		expectError    bool
		expectedInURL  []string
		expectedMethod string
	}{
		{
			name:           "Basic GET request to REST endpoint",
			args:           []string{"curl", "/rest/orgs"},
			globalFlags:    map[string]string{"version": "2024-10-15"},
			path:           "/rest/orgs",
			expectError:    false,
			expectedInURL:  []string{"version=2024-10-15"},
			expectedMethod: "GET",
		},
		{
			name:           "POST request with data",
			args:           []string{"curl", "-X", "POST", "-d", `{"name":"test"}`, "/rest/orgs"},
			globalFlags:    map[string]string{"version": "2024-10-15"},
			path:           "/rest/orgs",
			expectError:    false,
			expectedInURL:  []string{"version=2024-10-15"},
			expectedMethod: "POST",
		},
		{
			name:           "GET request to non-REST endpoint",
			args:           []string{"curl", "/v1/user"},
			globalFlags:    map[string]string{"version": "2024-10-15"},
			path:           "/v1/user",
			expectError:    false,
			expectedInURL:  []string{}, // No version parameter expected
			expectedMethod: "GET",
		},
		{
			name:           "Request with custom headers",
			args:           []string{"curl", "-H", "Authorization: Bearer test-token", "/auth/endpoint"},
			globalFlags:    map[string]string{"version": "2024-10-15"},
			path:           "/auth/endpoint",
			expectError:    false,
			expectedInURL:  []string{},
			expectedMethod: "GET",
		},
		{
			name:           "Request with custom version",
			args:           []string{"curl", "/rest/projects"},
			globalFlags:    map[string]string{"version": "2023-05-01"},
			path:           "/rest/projects",
			expectError:    false,
			expectedInURL:  []string{"version=2023-05-01"},
			expectedMethod: "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper for each test
			viper.Reset()
			viper.Set("endpoint", serverHost)

			// Set global flags
			for key, value := range tt.globalFlags {
				viper.Set(key, value)
			}

			// Create a test version of the curl command that uses HTTP
			testCurlCmd := &cobra.Command{
				Use:   "curl [path]",
				Short: "Make HTTP requests to the Snyk API",
				Args:  cobra.ExactArgs(1),
				RunE:  runCurlTest,
			}

			// Add curl-like flags
			testCurlCmd.Flags().StringVarP(&method, "request", "X", "GET", "HTTP method to use")
			testCurlCmd.Flags().StringSliceVarP(&headers, "header", "H", []string{}, "HTTP headers to send")
			testCurlCmd.Flags().StringVarP(&data, "data", "d", "", "Data to send in request body")
			testCurlCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Make the operation more talkative")
			testCurlCmd.Flags().BoolVarP(&silent, "silent", "s", false, "Silent mode")
			testCurlCmd.Flags().BoolVarP(&includeResp, "include", "i", false, "Include HTTP response headers in output")
			testCurlCmd.Flags().StringVarP(&userAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string")

			// Create a new root command for testing
			rootCmd := &cobra.Command{Use: "test"}
			rootCmd.AddCommand(testCurlCmd)

			// Capture output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Reset flags for each test
			resetCurlFlags()

			// Execute command
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()

			// Restore stdout and read output
			w.Close()
			os.Stdout = oldStdout

			buf := make([]byte, 1024)
			n, _ := r.Read(buf)
			output := string(buf[:n])

			// Check error expectation
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Verify URL components in output
			for _, expected := range tt.expectedInURL {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected %q in output, but got: %s", expected, output)
				}
			}

			// Verify method if no error expected
			if !tt.expectError && tt.expectedMethod != "" {
				if !strings.Contains(output, fmt.Sprintf(`method:%s`, tt.expectedMethod)) {
					t.Errorf("Expected method %s in output, but got: %s", tt.expectedMethod, output)
				}
			}
		})
	}
}

func TestCurlCommandWithVerboseOutput(t *testing.T) {
	server := createMockServer()
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "http://")

	// Reset viper
	viper.Reset()
	viper.Set("endpoint", serverHost)
	viper.Set("version", "2024-10-15")

	// Create test command
	testCurlCmd := &cobra.Command{
		Use:  "curl [path]",
		Args: cobra.ExactArgs(1),
		RunE: runCurlTest,
	}
	testCurlCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose")

	rootCmd := &cobra.Command{Use: "test"}
	rootCmd.AddCommand(testCurlCmd)

	// Capture stderr for verbose output
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Reset flags
	resetCurlFlags()

	// Execute with verbose flag
	rootCmd.SetArgs([]string{"curl", "-v", "/rest/test"})
	err := rootCmd.Execute()

	// Restore stderr and read output
	w.Close()
	os.Stderr = oldStderr

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	stderrOutput := string(buf[:n])

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check that verbose output contains expected elements
	expectedVerbose := []string{
		"* Requesting GET",
		"* Making request...",
		"* Response:",
	}

	for _, expected := range expectedVerbose {
		if !strings.Contains(stderrOutput, expected) {
			t.Errorf("Expected %q in verbose output, but got: %s", expected, stderrOutput)
		}
	}
}

func TestCurlCommandErrorHandling(t *testing.T) {
	server := createMockServer()
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "http://")

	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "Request to error endpoint",
			args:        []string{"curl", "-v", "/error"},
			expectError: true,
		},
		{
			name:        "Request to auth endpoint without token",
			args:        []string{"curl", "-v", "/auth"},
			expectError: true,
		},
		{
			name:        "Request with invalid header format",
			args:        []string{"curl", "-H", "InvalidHeader", "/test"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper
			viper.Reset()
			viper.Set("endpoint", serverHost)

			// Create test command
			testCurlCmd := &cobra.Command{
				Use:  "curl [path]",
				Args: cobra.ExactArgs(1),
				RunE: runCurlTest,
			}
			testCurlCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose")
			testCurlCmd.Flags().StringSliceVarP(&headers, "header", "H", []string{}, "Headers")

			rootCmd := &cobra.Command{Use: "test"}
			rootCmd.AddCommand(testCurlCmd)

			// Reset flags
			resetCurlFlags()

			// Execute command
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCurlCommandWithIncludeHeaders(t *testing.T) {
	server := createMockServer()
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "http://")

	// Reset viper
	viper.Reset()
	viper.Set("endpoint", serverHost)

	// Create test command
	testCurlCmd := &cobra.Command{
		Use:  "curl [path]",
		Args: cobra.ExactArgs(1),
		RunE: runCurlTest,
	}
	testCurlCmd.Flags().BoolVarP(&includeResp, "include", "i", false, "Include headers")

	rootCmd := &cobra.Command{Use: "test"}
	rootCmd.AddCommand(testCurlCmd)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Reset flags
	resetCurlFlags()

	// Execute with include headers flag
	rootCmd.SetArgs([]string{"curl", "-i", "/test"})
	err := rootCmd.Execute()

	// Restore stdout and read output
	w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check that response headers are included
	expectedHeaders := []string{
		"HTTP/", // HTTP version line
		"Content-Type:",
	}

	for _, expected := range expectedHeaders {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected %q in output with headers, but got: %s", expected, output)
		}
	}
}

// Helper function to reset curl command flags between tests
func resetCurlFlags() {
	method = "GET"
	headers = []string{}
	data = ""
	verbose = false
	silent = false
	includeResp = false
	userAgent = "snyk-api-cli/1.0"
}

func TestCurlCommandWithOAuth(t *testing.T) {
	server := createMockServer()
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "http://")

	tests := []struct {
		name              string
		args              []string
		mockSnykCommand   bool
		mockTokenOutput   string
		expectedAuthValue string
		expectVerboseMsg  string
	}{
		{
			name:              "Manual auth header takes precedence",
			args:              []string{"curl", "-v", "-H", "Authorization: Bearer manual_token", "/test"},
			mockSnykCommand:   true,
			mockTokenOutput:   `{"access_token":"auto_token","refresh_token":"refresh","expiry":"2025-12-31T23:59:59Z"}`,
			expectedAuthValue: "Bearer manual_token",
			expectVerboseMsg:  "* Using manual authorization header",
		},
		{
			name:              "Automatic auth when no manual header provided",
			args:              []string{"curl", "-v", "/test"},
			mockSnykCommand:   true,
			mockTokenOutput:   `{"access_token":"auto_token","refresh_token":"refresh","expiry":"2025-12-31T23:59:59Z"}`,
			expectedAuthValue: "Bearer auto_token",
			expectVerboseMsg:  "* Added automatic authorization header",
		},
		{
			name:              "No auth when snyk CLI unavailable",
			args:              []string{"curl", "-v", "/test"},
			mockSnykCommand:   false,
			mockTokenOutput:   "",
			expectedAuthValue: "",
			expectVerboseMsg:  "* Warning: failed to get automatic auth",
		},
		{
			name:              "Other headers don't interfere with auth detection",
			args:              []string{"curl", "-v", "-H", "Content-Type: application/json", "/test"},
			mockSnykCommand:   true,
			mockTokenOutput:   `{"access_token":"auto_token","refresh_token":"refresh","expiry":"2025-12-31T23:59:59Z"}`,
			expectedAuthValue: "Bearer auto_token",
			expectVerboseMsg:  "* Added automatic authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper
			viper.Reset()
			viper.Set("endpoint", serverHost)

			// Create test command with mocked OAuth functions
			testCurlCmd := createTestCurlCommand(tt.mockSnykCommand, tt.mockTokenOutput)
			rootCmd := &cobra.Command{Use: "test"}
			rootCmd.AddCommand(testCurlCmd)

			// Capture stderr for verbose output
			oldStderr := os.Stderr
			rErr, wErr, _ := os.Pipe()
			os.Stderr = wErr

			// Capture stdout for response
			oldStdout := os.Stdout
			rOut, wOut, _ := os.Pipe()
			os.Stdout = wOut

			// Reset flags
			resetCurlFlags()

			// Execute command
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()

			// Restore stderr and stdout
			wErr.Close()
			wOut.Close()
			os.Stderr = oldStderr
			os.Stdout = oldStdout

			// Read outputs
			bufErr := make([]byte, 2048)
			nErr, _ := rErr.Read(bufErr)
			stderrOutput := string(bufErr[:nErr])

			bufOut := make([]byte, 2048)
			nOut, _ := rOut.Read(bufOut)
			stdoutOutput := string(bufOut[:nOut])

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check for expected verbose message
			if tt.expectVerboseMsg != "" {
				if !strings.Contains(stderrOutput, tt.expectVerboseMsg) {
					t.Errorf("Expected verbose message %q in stderr, but got: %s", tt.expectVerboseMsg, stderrOutput)
				}
			}

			// Check for expected auth header in response
			if tt.expectedAuthValue != "" {
				if !strings.Contains(stdoutOutput, tt.expectedAuthValue) {
					t.Errorf("Expected auth value %q in response, but got: %s", tt.expectedAuthValue, stdoutOutput)
				}
			} else {
				// Ensure no Authorization header is present
				if strings.Contains(stdoutOutput, "Authorization") {
					t.Errorf("Expected no Authorization header but found one in: %s", stdoutOutput)
				}
			}
		})
	}
}

func TestOAuthTokenExpiry(t *testing.T) {
	server := createMockServer()
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "http://")

	tests := []struct {
		name            string
		tokenOutput     string
		expectWarning   bool
		warningContains string
	}{
		{
			name:            "Valid non-expired token",
			tokenOutput:     `{"access_token":"valid_token","refresh_token":"refresh","expiry":"2025-12-31T23:59:59Z"}`,
			expectWarning:   false,
			warningContains: "",
		},
		{
			name:            "Expired token with refresh token",
			tokenOutput:     `{"access_token":"expired_token","refresh_token":"refresh_token","expiry":"2020-01-01T00:00:00Z"}`,
			expectWarning:   true,
			warningContains: "failed to refresh token",
		},
		{
			name:            "Expired token without refresh token",
			tokenOutput:     `{"access_token":"expired_token","refresh_token":"","expiry":"2020-01-01T00:00:00Z"}`,
			expectWarning:   true,
			warningContains: "token expired and no refresh token available",
		},
		{
			name:            "Token expiring soon",
			tokenOutput:     fmt.Sprintf(`{"access_token":"expiring_token","refresh_token":"refresh","expiry":"%s"}`, time.Now().Add(2*time.Minute).Format(time.RFC3339)),
			expectWarning:   true,
			warningContains: "failed to refresh token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper
			viper.Reset()
			viper.Set("endpoint", serverHost)

			// Create test command with mocked OAuth functions
			testCurlCmd := createTestCurlCommand(true, tt.tokenOutput)
			rootCmd := &cobra.Command{Use: "test"}
			rootCmd.AddCommand(testCurlCmd)

			// Capture stderr for verbose output
			oldStderr := os.Stderr
			rErr, wErr, _ := os.Pipe()
			os.Stderr = wErr

			// Reset flags
			resetCurlFlags()

			// Execute command with verbose flag
			rootCmd.SetArgs([]string{"curl", "-v", "/test"})
			err := rootCmd.Execute()

			// Restore stderr
			wErr.Close()
			os.Stderr = oldStderr

			// Read stderr output
			bufErr := make([]byte, 2048)
			nErr, _ := rErr.Read(bufErr)
			stderrOutput := string(bufErr[:nErr])

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check for expected warning
			if tt.expectWarning {
				if tt.warningContains != "" && !strings.Contains(stderrOutput, tt.warningContains) {
					t.Errorf("Expected warning containing %q in stderr, but got: %s", tt.warningContains, stderrOutput)
				}
			}
		})
	}
}

// createTestCurlCommand creates a test version of the curl command with mocked OAuth functionality
func createTestCurlCommand(mockSnykAvailable bool, mockTokenOutput string) *cobra.Command {
	testCurlCmd := &cobra.Command{
		Use:  "curl [path]",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCurlWithMockedAuth(cmd, args, mockSnykAvailable, mockTokenOutput)
		},
	}

	// Add curl-like flags
	testCurlCmd.Flags().StringVarP(&method, "request", "X", "GET", "HTTP method to use")
	testCurlCmd.Flags().StringSliceVarP(&headers, "header", "H", []string{}, "HTTP headers to send")
	testCurlCmd.Flags().StringVarP(&data, "data", "d", "", "Data to send in request body")
	testCurlCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Make the operation more talkative")
	testCurlCmd.Flags().BoolVarP(&silent, "silent", "s", false, "Silent mode")
	testCurlCmd.Flags().BoolVarP(&includeResp, "include", "i", false, "Include HTTP response headers in output")
	testCurlCmd.Flags().StringVarP(&userAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string")

	return testCurlCmd
}

// runCurlWithMockedAuth is a version of runCurl with mocked authentication functionality for testing
func runCurlWithMockedAuth(_ *cobra.Command, args []string, mockSnykAvailable bool, mockTokenOutput string) error {
	path := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the full URL (using HTTP for testing)
	fullURL, err := buildTestURL(endpoint, path, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "* Requesting %s %s\n", method, fullURL)
	}

	// Create the HTTP request
	req, err := createRequest(method, fullURL, data)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with precedence: Authorization header > SNYK_TOKEN > OAuth
	if verbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := getMockedAuthHeader(headers, mockSnykAvailable, mockTokenOutput)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		// getMockedAuthHeader returns non-empty only for automatic auth (SNYK_TOKEN or OAuth)
		headers = append(headers, fmt.Sprintf("Authorization: %s", authHeader))
		if verbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if verbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Add headers
	err = addHeaders(req, headers, userAgent)
	if err != nil {
		return fmt.Errorf("failed to add headers: %w", err)
	}

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response
	return handleResponse(resp, includeResp, verbose, silent)
}

// getMockedAuthHeader mocks the full authentication precedence logic for testing
func getMockedAuthHeader(manualHeaders []string, snykAvailable bool, tokenOutput string) (string, error) {
	// Get SNYK_TOKEN from environment
	snykToken := os.Getenv("SNYK_TOKEN")

	// Get OAuth token string from mock
	var oauthTokenStr string
	if snykAvailable && tokenOutput != "" {
		token, err := parseSnykToken(tokenOutput)
		if err == nil && !isTokenExpired(token) {
			oauthTokenStr = token.AccessToken
		}
	}

	// No client credentials in test mock
	shouldUse, authHeader, source := determineAuthMethod(manualHeaders, "", "", snykToken, oauthTokenStr)

	if shouldUse {
		if verbose {
			fmt.Printf("* Using %s authentication\n", source)
		}
		return authHeader, nil
	}

	// Manual auth or no auth available
	if source == "manual" && verbose {
		fmt.Println("* Using manual Authorization header")
	}

	return "", nil
}



func TestCurlCommandSnykTokenIntegration(t *testing.T) {
	// Test SNYK_TOKEN environment variable integration
	tests := []struct {
		name           string
		snykToken      string
		manualHeaders  []string
		mockSnykOutput string
		expectToken    string
		expectError    bool
	}{
		{
			name:          "SNYK_TOKEN used when set",
			snykToken:     "env_test_token",
			manualHeaders: []string{},
			expectToken:   "token env_test_token",
			expectError:   false,
		},
		{
			name:          "Manual auth header overrides SNYK_TOKEN",
			snykToken:     "env_test_token",
			manualHeaders: []string{"Authorization: Bearer manual_token"},
			expectToken:   "Bearer manual_token",
			expectError:   false,
		},
		{
			name:           "SNYK_TOKEN overrides OAuth when both available",
			snykToken:      "env_test_token",
			manualHeaders:  []string{},
			mockSnykOutput: `{"access_token":"oauth_token","refresh_token":"refresh123","expiry":"2030-12-31T23:59:59Z"}`,
			expectToken:    "token env_test_token",
			expectError:    false,
		},
		{
			name:           "OAuth used when SNYK_TOKEN empty",
			snykToken:      "",
			manualHeaders:  []string{},
			mockSnykOutput: `{"access_token":"oauth_token","refresh_token":"refresh123","expiry":"2030-12-31T23:59:59Z"}`,
			expectToken:    "Bearer oauth_token",
			expectError:    false,
		},
		{
			name:           "Whitespace SNYK_TOKEN falls back to OAuth",
			snykToken:      "   ",
			manualHeaders:  []string{},
			mockSnykOutput: `{"access_token":"oauth_token","refresh_token":"refresh123","expiry":"2030-12-31T23:59:59Z"}`,
			expectToken:    "Bearer oauth_token",
			expectError:    false,
		},
		{
			name:           "No auth when neither SNYK_TOKEN nor OAuth available",
			snykToken:      "",
			manualHeaders:  []string{},
			mockSnykOutput: "",
			expectToken:    "",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authHeader := r.Header.Get("Authorization")

				// Verify expected auth header
				if tt.expectToken != "" && authHeader != tt.expectToken {
					t.Errorf("Expected Authorization header %q, got %q", tt.expectToken, authHeader)
				}

				if tt.expectToken == "" && authHeader != "" {
					t.Errorf("Expected no Authorization header, got %q", authHeader)
				}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"result": "success"}`))
			}))
			defer server.Close()

			// Parse server URL to get the host
			u, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("Failed to parse server URL: %v", err)
			}

			// Set environment variables
			oldSnykToken := os.Getenv("SNYK_TOKEN")
			if tt.snykToken != "" {
				os.Setenv("SNYK_TOKEN", tt.snykToken)
			} else {
				os.Unsetenv("SNYK_TOKEN")
			}
			defer func() {
				if oldSnykToken != "" {
					os.Setenv("SNYK_TOKEN", oldSnykToken)
				} else {
					os.Unsetenv("SNYK_TOKEN")
				}
			}()

			// Reset global variables
			method = "GET"
			headers = tt.manualHeaders
			data = ""
			verbose = false
			silent = false
			includeResp = false
			userAgent = "snyk-api-cli/1.0"

			// Set endpoint to test server
			viper.Set("endpoint", u.Host)
			viper.Set("version", "2024-10-15")

			// Use mocked auth command for testing
			cmd := createTestCurlCommand(tt.mockSnykOutput != "", tt.mockSnykOutput)

			// Build command line args with headers
			args := []string{"/rest/test"}
			for _, header := range tt.manualHeaders {
				args = append([]string{"-H", header}, args...)
			}

			// Parse flags to set the global variables correctly
			cmd.ParseFlags(args)

			// Run the command with just the path
			err = cmd.RunE(cmd, []string{"/rest/test"})

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestCurlCommandAuthPrecedenceIntegration(t *testing.T) {
	// Test full authentication precedence in real curl command execution
	tests := []struct {
		name           string
		snykTokenEnv   string
		manualHeaders  []string
		mockSnykOutput string
		expectedAuth   string
		expectedSource string
	}{
		{
			name:           "Manual header wins over all",
			snykTokenEnv:   "env_token",
			manualHeaders:  []string{"Authorization: Bearer manual_token", "Content-Type: application/json"},
			mockSnykOutput: `{"access_token":"oauth_token","refresh_token":"refresh123","expiry":"2030-12-31T23:59:59Z"}`,
			expectedAuth:   "Bearer manual_token",
			expectedSource: "manual",
		},
		{
			name:           "SNYK_TOKEN wins over OAuth",
			snykTokenEnv:   "env_token",
			manualHeaders:  []string{"Content-Type: application/json"},
			mockSnykOutput: `{"access_token":"oauth_token","refresh_token":"refresh123","expiry":"2030-12-31T23:59:59Z"}`,
			expectedAuth:   "token env_token",
			expectedSource: "env",
		},
		{
			name:           "OAuth used when no higher precedence",
			snykTokenEnv:   "",
			manualHeaders:  []string{"Content-Type: application/json"},
			mockSnykOutput: `{"access_token":"oauth_token","refresh_token":"refresh123","expiry":"2030-12-31T23:59:59Z"}`,
			expectedAuth:   "Bearer oauth_token",
			expectedSource: "oauth",
		},
		{
			name:           "No auth when nothing available",
			snykTokenEnv:   "",
			manualHeaders:  []string{"Content-Type: application/json"},
			mockSnykOutput: "",
			expectedAuth:   "",
			expectedSource: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authHeader := r.Header.Get("Authorization")

				if tt.expectedAuth != "" && authHeader != tt.expectedAuth {
					t.Errorf("Expected Authorization header %q, got %q", tt.expectedAuth, authHeader)
				}

				if tt.expectedAuth == "" && authHeader != "" {
					t.Errorf("Expected no Authorization header, got %q", authHeader)
				}

				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"result": "success"}`))
			}))
			defer server.Close()

			// Parse server URL
			u, err := url.Parse(server.URL)
			if err != nil {
				t.Fatalf("Failed to parse server URL: %v", err)
			}

			// Set up environment
			oldSnykToken := os.Getenv("SNYK_TOKEN")
			if tt.snykTokenEnv != "" {
				os.Setenv("SNYK_TOKEN", tt.snykTokenEnv)
			} else {
				os.Unsetenv("SNYK_TOKEN")
			}
			defer func() {
				if oldSnykToken != "" {
					os.Setenv("SNYK_TOKEN", oldSnykToken)
				} else {
					os.Unsetenv("SNYK_TOKEN")
				}
			}()

			// Reset command state
			method = "GET"
			headers = tt.manualHeaders
			data = ""
			verbose = false
			silent = false
			includeResp = false
			userAgent = "snyk-api-cli/1.0"

			// Configure for test server
			viper.Set("endpoint", u.Host)
			viper.Set("version", "2024-10-15")

			// Execute command with mocking
			cmd := createTestCurlCommand(tt.mockSnykOutput != "", tt.mockSnykOutput)

			// Build command line args with headers
			args := []string{"/rest/test"}
			for _, header := range tt.manualHeaders {
				args = append([]string{"-H", header}, args...)
			}

			// Parse flags to set the global variables correctly
			cmd.ParseFlags(args)

			// Run the command with just the path
			err = cmd.RunE(cmd, []string{"/rest/test"})
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
