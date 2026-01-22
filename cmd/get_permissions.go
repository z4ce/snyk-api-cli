package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

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

	// Build request body
	requestBody, err := buildGetPermissionsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     getPermissionsVerbose,
		Silent:      getPermissionsSilent,
		IncludeResp: getPermissionsIncludeResp,
		UserAgent:   getPermissionsUserAgent,
	})
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
