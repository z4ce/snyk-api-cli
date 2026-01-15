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

// CreateOrgAppCmd represents the create-org-app command
var CreateOrgAppCmd = &cobra.Command{
	Use:   "create-org-app [org_id]",
	Short: "Create a Snyk App for an organization",
	Long: `Create a Snyk App for an organization in the Snyk API.

This command creates a new Snyk App with the specified configuration including
redirect URIs, scopes, and access token TTL settings.

Examples:
  snyk-api-cli create-org-app 12345678-1234-5678-9012-123456789012 --name "My App" --redirect-uris "https://example.com/callback" --scopes "org.read"
  snyk-api-cli create-org-app 12345678-1234-5678-9012-123456789012 --name "My App" --redirect-uris "https://example.com/callback" --scopes "org.read,org.write" --context "user" --access-token-ttl 7200`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateOrgApp,
}

var (
	createOrgAppName                string
	createOrgAppRedirectUris        []string
	createOrgAppScopes              []string
	createOrgAppContext             string
	createOrgAppAccessTokenTTL      int
	createOrgAppVerbose             bool
	createOrgAppSilent              bool
	createOrgAppIncludeResp         bool
	createOrgAppUserAgent           string
)

func init() {
	// Add flags for request body attributes
	CreateOrgAppCmd.Flags().StringVar(&createOrgAppName, "name", "", "App display name (required)")
	CreateOrgAppCmd.Flags().StringSliceVar(&createOrgAppRedirectUris, "redirect-uris", []string{}, "Allowed callback URIs (required, can be used multiple times)")
	CreateOrgAppCmd.Flags().StringSliceVar(&createOrgAppScopes, "scopes", []string{}, "Authorized app scopes (required, can be used multiple times)")
	CreateOrgAppCmd.Flags().StringVar(&createOrgAppContext, "context", "tenant", "App context (tenant or user)")
	CreateOrgAppCmd.Flags().IntVar(&createOrgAppAccessTokenTTL, "access-token-ttl", 0, "Access token TTL in seconds (3600-86400)")
	
	// Add standard flags like curl command
	CreateOrgAppCmd.Flags().BoolVarP(&createOrgAppVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateOrgAppCmd.Flags().BoolVarP(&createOrgAppSilent, "silent", "s", false, "Silent mode")
	CreateOrgAppCmd.Flags().BoolVarP(&createOrgAppIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateOrgAppCmd.Flags().StringVarP(&createOrgAppUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateOrgAppCmd.MarkFlagRequired("name")
	CreateOrgAppCmd.MarkFlagRequired("redirect-uris")
	CreateOrgAppCmd.MarkFlagRequired("scopes")
}

func runCreateOrgApp(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateOrgAppURL(endpoint, orgID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createOrgAppVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateOrgAppRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createOrgAppVerbose {
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
	if createOrgAppVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createOrgAppVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createOrgAppVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createOrgAppVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createOrgAppUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createOrgAppVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleCreateOrgAppResponse(resp, createOrgAppIncludeResp, createOrgAppVerbose, createOrgAppSilent)
}

func buildCreateOrgAppURL(endpoint, orgID, version string) (string, error) {
	// Build base URL with org_id path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/creations", endpoint, orgID)

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

func buildCreateOrgAppRequestBody() (string, error) {
	// Validate required fields
	if createOrgAppName == "" {
		return "", fmt.Errorf("name is required")
	}
	if len(createOrgAppRedirectUris) == 0 {
		return "", fmt.Errorf("at least one redirect URI is required")
	}
	if len(createOrgAppScopes) == 0 {
		return "", fmt.Errorf("at least one scope is required")
	}

	// Validate context
	if createOrgAppContext != "tenant" && createOrgAppContext != "user" {
		return "", fmt.Errorf("context must be 'tenant' or 'user'")
	}

	// Validate access token TTL if provided
	if createOrgAppAccessTokenTTL > 0 && (createOrgAppAccessTokenTTL < 3600 || createOrgAppAccessTokenTTL > 86400) {
		return "", fmt.Errorf("access token TTL must be between 3600 and 86400 seconds")
	}

	// Build JSON:API format request body
	attributes := map[string]interface{}{
		"name":          createOrgAppName,
		"redirect_uris": createOrgAppRedirectUris,
		"scopes":        createOrgAppScopes,
		"context":       createOrgAppContext,
	}

	// Add access token TTL if provided
	if createOrgAppAccessTokenTTL > 0 {
		attributes["access_token_ttl_seconds"] = createOrgAppAccessTokenTTL
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

func handleCreateOrgAppResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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