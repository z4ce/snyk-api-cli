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

// GetPermissionsCmd represents the get-permissions command
var GetPermissionsCmd = &cobra.Command{
	Use:   "get-permissions [org_id]",
	Short: "Get cloud permissions for a specific organization in Snyk",
	Long: `Get cloud permissions for a specific organization in the Snyk API.

This command retrieves cloud permissions for a specific organization by its ID.
The organization ID must be provided as a required argument, and the platform
and type must be provided as flags.

Examples:
  snyk-api-cli get-permissions 12345678-1234-1234-1234-123456789012 --platform aws --type tf
  snyk-api-cli get-permissions 12345678-1234-1234-1234-123456789012 --platform azure --type cf --verbose
  snyk-api-cli get-permissions 12345678-1234-1234-1234-123456789012 --platform google --type bash --options "custom-options"`,
	Args: cobra.ExactArgs(1),
	RunE: runGetPermissions,
}

var (
	getPermissionsPlatform    string
	getPermissionsType        string
	getPermissionsOptions     string
	getPermissionsVerbose     bool
	getPermissionsSilent      bool
	getPermissionsIncludeResp bool
	getPermissionsUserAgent   string
)

func init() {
	// Add flags for request body attributes
	GetPermissionsCmd.Flags().StringVar(&getPermissionsPlatform, "platform", "", "Platform type (required: aws, azure, google)")
	GetPermissionsCmd.Flags().StringVar(&getPermissionsType, "type", "", "Permissions type (required: cf, tf, bash)")
	GetPermissionsCmd.Flags().StringVar(&getPermissionsOptions, "options", "", "Additional options (optional)")
	
	// Add standard flags like other commands
	GetPermissionsCmd.Flags().BoolVarP(&getPermissionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetPermissionsCmd.Flags().BoolVarP(&getPermissionsSilent, "silent", "s", false, "Silent mode")
	GetPermissionsCmd.Flags().BoolVarP(&getPermissionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetPermissionsCmd.Flags().StringVarP(&getPermissionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	GetPermissionsCmd.MarkFlagRequired("platform")
	GetPermissionsCmd.MarkFlagRequired("type")
}

func runGetPermissions(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate platform and type values
	if err := validateGetPermissionsFlags(); err != nil {
		return err
	}

	// Build the URL
	fullURL, err := buildGetPermissionsURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getPermissionsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildGetPermissionsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if getPermissionsVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getPermissionsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getPermissionsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getPermissionsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getPermissionsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getPermissionsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getPermissionsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetPermissionsResponse(resp, getPermissionsIncludeResp, getPermissionsVerbose, getPermissionsSilent)
}

func validateGetPermissionsFlags() error {
	// Validate platform
	validPlatforms := []string{"aws", "azure", "google"}
	platform := strings.ToLower(getPermissionsPlatform)
	isValidPlatform := false
	for _, validPlatform := range validPlatforms {
		if platform == validPlatform {
			isValidPlatform = true
			break
		}
	}
	if !isValidPlatform {
		return fmt.Errorf("invalid platform: %s (allowed values: %s)", getPermissionsPlatform, strings.Join(validPlatforms, ", "))
	}

	// Validate type
	validTypes := []string{"cf", "tf", "bash"}
	permType := strings.ToLower(getPermissionsType)
	isValidType := false
	for _, validType := range validTypes {
		if permType == validType {
			isValidType = true
			break
		}
	}
	if !isValidType {
		return fmt.Errorf("invalid type: %s (allowed values: %s)", getPermissionsType, strings.Join(validTypes, ", "))
	}

	return nil
}

func buildGetPermissionsURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with org ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/permissions", endpoint, orgID)

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

func buildGetPermissionsRequestBody() (string, error) {
	// Build request body according to the API specification
	attributes := map[string]interface{}{
		"platform": strings.ToLower(getPermissionsPlatform),
		"type":     strings.ToLower(getPermissionsType),
	}

	// Add optional options if provided
	if getPermissionsOptions != "" {
		attributes["options"] = getPermissionsOptions
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       "cloud_permissions",
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

func handleGetPermissionsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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