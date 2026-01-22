package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateAppCmd represents the update-app command
var UpdateAppCmd = &cobra.Command{
	Use:   "update-app [org_id] [client_id]",
	Short: "Update an app",
	Long: `Update an app in the Snyk API.

This command updates an app by providing the organization ID and client ID
as required arguments. The app attributes can be updated via the available flags.

Examples:
  snyk-api-cli update-app 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --name "My Updated App"
  snyk-api-cli update-app 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --name "Updated App" --access-token-ttl 7200 --redirect-uris "https://example.com/callback" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateApp,
}

var (
	updateAppName                  string
	updateAppAccessTokenTTLSeconds int
	updateAppRedirectURIs          []string
	updateAppVerbose               bool
	updateAppSilent                bool
	updateAppIncludeResp           bool
	updateAppUserAgent             string
)

func init() {
	// Add flags for request body attributes
	UpdateAppCmd.Flags().StringVar(&updateAppName, "name", "", "Name of the app")
	UpdateAppCmd.Flags().IntVar(&updateAppAccessTokenTTLSeconds, "access-token-ttl", 0, "The access token time to live for your app, in seconds (3600-86400)")
	UpdateAppCmd.Flags().StringSliceVar(&updateAppRedirectURIs, "redirect-uris", []string{}, "List of allowed redirect URIs to call back after authentication")

	// Add standard flags like other commands
	UpdateAppCmd.Flags().BoolVarP(&updateAppVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateAppCmd.Flags().BoolVarP(&updateAppSilent, "silent", "s", false, "Silent mode")
	UpdateAppCmd.Flags().BoolVarP(&updateAppIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateAppCmd.Flags().StringVarP(&updateAppUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runUpdateApp(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	clientID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateAppURL(endpoint, version, orgID, clientID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateAppRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateAppVerbose,
		Silent:      updateAppSilent,
		IncludeResp: updateAppIncludeResp,
		UserAgent:   updateAppUserAgent,
	})
}

func buildUpdateAppURL(endpoint, version, orgID, clientID string) (string, error) {
	// Build base URL with org ID and client ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/%s", endpoint, orgID, clientID)

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

func buildUpdateAppRequestBody() (string, error) {
	// Build attributes map with only provided fields
	attributes := map[string]interface{}{}

	// Add name if provided
	if updateAppName != "" {
		attributes["name"] = updateAppName
	}

	// Add access token TTL if provided
	if updateAppAccessTokenTTLSeconds != 0 {
		// Validate access token TTL
		if updateAppAccessTokenTTLSeconds < 3600 || updateAppAccessTokenTTLSeconds > 86400 {
			return "", fmt.Errorf("access-token-ttl must be between 3600 and 86400")
		}
		attributes["access_token_ttl_seconds"] = updateAppAccessTokenTTLSeconds
	}

	// Add redirect URIs if provided
	if len(updateAppRedirectURIs) > 0 {
		attributes["redirect_uris"] = updateAppRedirectURIs
	}

	// If no attributes provided, return error
	if len(attributes) == 0 {
		return "", fmt.Errorf("at least one attribute must be provided for update (name, access-token-ttl, or redirect-uris)")
	}

	// Build JSON:API format request body according to the specification
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
