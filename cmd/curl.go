package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CurlCmd represents the curl command
var CurlCmd = &cobra.Command{
	Use:   "curl [path]",
	Short: "Make HTTP requests to the Snyk API",
	Long: `Make HTTP requests to the Snyk API with curl-like functionality.
This command automatically handles Snyk API specifics like version parameters
for REST endpoints and proper base URL handling.

Examples:
  snyk-api-cli curl /rest/orgs
  snyk-api-cli curl -X POST -d '{"name":"test"}' /rest/orgs/123/projects
  snyk-api-cli curl -H "Authorization: Bearer token" /v1/user`,
	Args: cobra.ExactArgs(1),
	RunE: runCurl,
}

var (
	method      string
	headers     []string
	data        string
	verbose     bool
	silent      bool
	includeResp bool
	userAgent   string
)

func init() {
	// Add curl-like flags
	CurlCmd.Flags().StringVarP(&method, "request", "X", "GET", "HTTP method to use")
	CurlCmd.Flags().StringSliceVarP(&headers, "header", "H", []string{}, "HTTP headers to send (can be used multiple times)")
	CurlCmd.Flags().StringVarP(&data, "data", "d", "", "Data to send in request body")
	CurlCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Make the operation more talkative")
	CurlCmd.Flags().BoolVarP(&silent, "silent", "s", false, "Silent mode")
	CurlCmd.Flags().BoolVarP(&includeResp, "include", "i", false, "Include HTTP response headers in output")
	CurlCmd.Flags().StringVarP(&userAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runCurl(cmd *cobra.Command, args []string) error {
	path := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the full URL
	fullURL, err := buildURL(endpoint, path, version)
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

	authHeader, err := buildAuthHeader(headers)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		// buildAuthHeader returns non-empty only for automatic auth (SNYK_TOKEN or OAuth)
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

func buildURL(endpoint, path, version string) (string, error) {
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Build base URL
	baseURL := fmt.Sprintf("https://%s", endpoint)

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

func createRequest(method, url, data string) (*http.Request, error) {
	var body io.Reader
	if data != "" {
		body = strings.NewReader(data)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	// Set default content type for POST/PUT with data
	if data != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

func addHeaders(req *http.Request, headers []string, userAgent string) error {
	// Set user agent
	req.Header.Set("User-Agent", userAgent)

	// Add custom headers
	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header format: %s (expected 'Key: Value')", header)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		req.Header.Set(key, value)
	}

	return nil
}

func handleResponse(resp *http.Response, includeResp, verbose, silent bool) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "* Response: %s\n", resp.Status)
	}

	// Print response headers if requested
	if includeResp {
		fmt.Printf("%s %s\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	// Read and print response body
	if !silent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		fmt.Print(string(body))
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}
