package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateAppCreationByIDCmd represents the update-app-creation-by-id command
var UpdateAppCreationByIDCmd = &cobra.Command{
	Use:   "update-app-creation-by-id [org_id] [app_id]",
	Short: "Update an app creation by ID",
	Long: `Update an app creation by ID in the Snyk API.

This command updates an app creation by providing the organization ID and app ID
as required arguments. The app attributes can be updated via the available flags.

Examples:
  snyk-api-cli update-app-creation-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --name "My Updated App"
  snyk-api-cli update-app-creation-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --name "Updated App" --access-token-ttl 7200 --redirect-uris "https://example.com/callback" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateAppCreationByID,
}

var (
	updateAppCreationByIDName                  string
	updateAppCreationByIDAccessTokenTTLSeconds int
	updateAppCreationByIDRedirectURIs          []string
	updateAppCreationByIDVerbose               bool
	updateAppCreationByIDSilent                bool
	updateAppCreationByIDIncludeResp           bool
	updateAppCreationByIDUserAgent             string
)

func init() {
	// Add flags for request body attributes
	UpdateAppCreationByIDCmd.Flags().StringVar(&updateAppCreationByIDName, "name", "", "Name of the app")
	UpdateAppCreationByIDCmd.Flags().IntVar(&updateAppCreationByIDAccessTokenTTLSeconds, "access-token-ttl", 0, "The access token time to live for your app, in seconds (3600-86400)")
	UpdateAppCreationByIDCmd.Flags().StringSliceVar(&updateAppCreationByIDRedirectURIs, "redirect-uris", []string{}, "List of allowed redirect URIs to call back after authentication")

	// Add standard flags like other commands
	UpdateAppCreationByIDCmd.Flags().BoolVarP(&updateAppCreationByIDVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateAppCreationByIDCmd.Flags().BoolVarP(&updateAppCreationByIDSilent, "silent", "s", false, "Silent mode")
	UpdateAppCreationByIDCmd.Flags().BoolVarP(&updateAppCreationByIDIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateAppCreationByIDCmd.Flags().StringVarP(&updateAppCreationByIDUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runUpdateAppCreationByID(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	appID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateAppCreationByIDURL(endpoint, version, orgID, appID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateAppCreationByIDRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateAppCreationByIDVerbose,
		Silent:      updateAppCreationByIDSilent,
		IncludeResp: updateAppCreationByIDIncludeResp,
		UserAgent:   updateAppCreationByIDUserAgent,
	})
}

func buildUpdateAppCreationByIDURL(endpoint, version, orgID, appID string) (string, error) {
	// Build base URL with org ID and app ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/creations/%s", endpoint, orgID, appID)

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

func buildUpdateAppCreationByIDRequestBody() (string, error) {
	// Build attributes map with only provided fields
	attributes := map[string]interface{}{}

	// Add name if provided
	if updateAppCreationByIDName != "" {
		attributes["name"] = updateAppCreationByIDName
	}

	// Add access token TTL if provided
	if updateAppCreationByIDAccessTokenTTLSeconds != 0 {
		// Validate access token TTL
		if updateAppCreationByIDAccessTokenTTLSeconds < 3600 || updateAppCreationByIDAccessTokenTTLSeconds > 86400 {
			return "", fmt.Errorf("access-token-ttl must be between 3600 and 86400")
		}
		attributes["access_token_ttl_seconds"] = updateAppCreationByIDAccessTokenTTLSeconds
	}

	// Add redirect URIs if provided
	if len(updateAppCreationByIDRedirectURIs) > 0 {
		attributes["redirect_uris"] = updateAppCreationByIDRedirectURIs
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
