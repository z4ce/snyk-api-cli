package cmd

import (
	"encoding/json"
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

// CreateAppCmd represents the create-app command
var CreateAppCmd = &cobra.Command{
	Use:   "create-app [org_id]",
	Short: "Create a new app in a specific organization in Snyk",
	Long: `Create a new app in a specific organization in the Snyk API.

This command creates a new app for a specific organization by its ID.
The organization ID must be provided as a required argument, and the app
name, redirect URIs, and scopes must be provided as flags.

Examples:
  snyk-api-cli create-app 12345678-1234-1234-1234-123456789012 --name "My App" --redirect-uris "https://example.com/callback" --scopes "org.read"
  snyk-api-cli create-app 12345678-1234-1234-1234-123456789012 --name "My App" --redirect-uris "https://example.com/callback,https://example.com/callback2" --scopes "org.read,org.write" --access-token-ttl-seconds 7200 --context "tenant"`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateApp,
}

var (
	createAppName                   string
	createAppRedirectURIs           []string
	createAppScopes                 []string
	createAppAccessTokenTTLSeconds  int
	createAppContext                string
	createAppVerbose                bool
	createAppSilent                 bool
	createAppIncludeResp            bool
	createAppUserAgent              string
)

func init() {
	// Add flags for request body attributes
	CreateAppCmd.Flags().StringVar(&createAppName, "name", "", "Name of the app to display to users during authorization flow (required)")
	CreateAppCmd.Flags().StringSliceVar(&createAppRedirectURIs, "redirect-uris", []string{}, "List of allowed redirect URIs to call back after authentication (required)")
	CreateAppCmd.Flags().StringSliceVar(&createAppScopes, "scopes", []string{}, "The scopes this app is allowed to request during authorization (required)")
	CreateAppCmd.Flags().IntVar(&createAppAccessTokenTTLSeconds, "access-token-ttl-seconds", 0, "The access token time to live for your app, in seconds (3600-86400)")
	CreateAppCmd.Flags().StringVar(&createAppContext, "context", "", "Allow installing the app to a org/group or to a user (tenant or user)")
	
	// Add standard flags like other commands
	CreateAppCmd.Flags().BoolVarP(&createAppVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateAppCmd.Flags().BoolVarP(&createAppSilent, "silent", "s", false, "Silent mode")
	CreateAppCmd.Flags().BoolVarP(&createAppIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateAppCmd.Flags().StringVarP(&createAppUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateAppCmd.MarkFlagRequired("name")
	CreateAppCmd.MarkFlagRequired("redirect-uris")
	CreateAppCmd.MarkFlagRequired("scopes")
}

func runCreateApp(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateAppURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createAppVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateAppRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createAppVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createAppVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createAppVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createAppVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createAppVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createAppUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createAppVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateAppResponse(resp, createAppIncludeResp, createAppVerbose, createAppSilent)
}

func buildCreateAppURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add version parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func buildCreateAppRequestBody() (string, error) {
	// Validate required fields
	if createAppName == "" {
		return "", fmt.Errorf("name is required")
	}
	if len(createAppRedirectURIs) == 0 {
		return "", fmt.Errorf("redirect-uris are required")
	}
	if len(createAppScopes) == 0 {
		return "", fmt.Errorf("scopes are required")
	}

	// Validate access token TTL if provided
	if createAppAccessTokenTTLSeconds != 0 && (createAppAccessTokenTTLSeconds < 3600 || createAppAccessTokenTTLSeconds > 86400) {
		return "", fmt.Errorf("access-token-ttl-seconds must be between 3600 and 86400")
	}

	// Validate context if provided
	if createAppContext != "" && createAppContext != "tenant" && createAppContext != "user" {
		return "", fmt.Errorf("context must be either 'tenant' or 'user'")
	}

	// Build JSON:API format request body according to the specification
	attributes := map[string]interface{}{
		"name":          createAppName,
		"redirect_uris": createAppRedirectURIs,
		"scopes":        createAppScopes,
	}

	// Add optional fields if provided
	if createAppAccessTokenTTLSeconds != 0 {
		attributes["access_token_ttl_seconds"] = createAppAccessTokenTTLSeconds
	}
	if createAppContext != "" {
		attributes["context"] = createAppContext
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       "app",
			"attributes": attributes,
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleCreateAppResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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