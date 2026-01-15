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

	if updateAppCreationByIDVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateAppCreationByIDRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateAppCreationByIDVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("PATCH", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateAppCreationByIDVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateAppCreationByIDVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateAppCreationByIDVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateAppCreationByIDVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateAppCreationByIDUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateAppCreationByIDVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateAppCreationByIDResponse(resp, updateAppCreationByIDIncludeResp, updateAppCreationByIDVerbose, updateAppCreationByIDSilent)
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

func handleUpdateAppCreationByIDResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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