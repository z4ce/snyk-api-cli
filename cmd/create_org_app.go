package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

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
	createOrgAppName           string
	createOrgAppRedirectUris   []string
	createOrgAppScopes         []string
	createOrgAppContext        string
	createOrgAppAccessTokenTTL int
	createOrgAppVerbose        bool
	createOrgAppSilent         bool
	createOrgAppIncludeResp    bool
	createOrgAppUserAgent      string
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

	// Build request body
	requestBody, err := buildCreateOrgAppRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createOrgAppVerbose,
		Silent:      createOrgAppSilent,
		IncludeResp: createOrgAppIncludeResp,
		UserAgent:   createOrgAppUserAgent,
	})
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
