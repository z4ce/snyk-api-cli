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

// UpdateIacSettingsForOrgCmd represents the update-iac-settings-for-org command
var UpdateIacSettingsForOrgCmd = &cobra.Command{
	Use:   "update-iac-settings-for-org [org_id]",
	Short: "Update Infrastructure as Code settings for an organization",
	Long: `Update Infrastructure as Code settings for an organization using the Snyk API.

This command updates the Infrastructure as Code settings for a specific organization by its ID.
The organization ID must be provided as a required argument.

Required permissions: Edit Organization (org.edit)

Examples:
  snyk-api-cli update-iac-settings-for-org 12345678-1234-1234-1234-123456789012 --type org_settings --custom-rules-enabled=true
  snyk-api-cli update-iac-settings-for-org 12345678-1234-1234-1234-123456789012 --type org_settings --custom-rules-enabled=false --custom-rules-oci-registry-url=https://example.com --custom-rules-oci-registry-tag=latest
  snyk-api-cli update-iac-settings-for-org 12345678-1234-1234-1234-123456789012 --type org_settings --custom-rules-inherit-from-parent=group --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runUpdateIacSettingsForOrg,
}

var (
	updateIacSettingsForOrgVerbose                     bool
	updateIacSettingsForOrgSilent                      bool
	updateIacSettingsForOrgIncludeResp                 bool
	updateIacSettingsForOrgUserAgent                   string
	updateIacSettingsForOrgDataType                    string
	updateIacSettingsForOrgCustomRulesEnabled          *bool
	updateIacSettingsForOrgCustomRulesOciURL           string
	updateIacSettingsForOrgCustomRulesOciTag           string
	updateIacSettingsForOrgCustomRulesInheritFromParent string
)

func init() {
	// Add standard flags like other commands
	UpdateIacSettingsForOrgCmd.Flags().BoolVarP(&updateIacSettingsForOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateIacSettingsForOrgCmd.Flags().BoolVarP(&updateIacSettingsForOrgSilent, "silent", "s", false, "Silent mode")
	UpdateIacSettingsForOrgCmd.Flags().BoolVarP(&updateIacSettingsForOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateIacSettingsForOrgCmd.Flags().StringVarP(&updateIacSettingsForOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Add request body flags
	UpdateIacSettingsForOrgCmd.Flags().StringVar(&updateIacSettingsForOrgDataType, "type", "org_settings", "The type field for the data object")
	
	// Custom rules flags
	var customRulesEnabled bool
	UpdateIacSettingsForOrgCmd.Flags().BoolVar(&customRulesEnabled, "custom-rules-enabled", false, "Enable or disable custom rules")
	UpdateIacSettingsForOrgCmd.Flags().StringVar(&updateIacSettingsForOrgCustomRulesOciURL, "custom-rules-oci-registry-url", "", "OCI registry URL for custom rules")
	UpdateIacSettingsForOrgCmd.Flags().StringVar(&updateIacSettingsForOrgCustomRulesOciTag, "custom-rules-oci-registry-tag", "", "OCI registry tag for custom rules")
	UpdateIacSettingsForOrgCmd.Flags().StringVar(&updateIacSettingsForOrgCustomRulesInheritFromParent, "custom-rules-inherit-from-parent", "", "Inherit custom rules from parent (e.g., 'group')")
	
	// Handle the boolean pointer for custom rules enabled
	UpdateIacSettingsForOrgCmd.Flags().Lookup("custom-rules-enabled").Changed = false
	UpdateIacSettingsForOrgCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("custom-rules-enabled") {
			updateIacSettingsForOrgCustomRulesEnabled = &customRulesEnabled
		}
		return nil
	}
}

func runUpdateIacSettingsForOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateIacSettingsForOrgURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateIacSettingsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateIacSettingsForOrgRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateIacSettingsForOrgVerbose {
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
	if updateIacSettingsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateIacSettingsForOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateIacSettingsForOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateIacSettingsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateIacSettingsForOrgUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateIacSettingsForOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateIacSettingsForOrgResponse(resp, updateIacSettingsForOrgIncludeResp, updateIacSettingsForOrgVerbose, updateIacSettingsForOrgSilent)
}

func buildUpdateIacSettingsForOrgURL(endpoint, version, orgID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/settings/iac", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func buildUpdateIacSettingsForOrgRequestBody() (string, error) {
	// Build the request body according to the API specification
	requestBody := map[string]interface{}{
		"data": map[string]interface{}{
			"type": updateIacSettingsForOrgDataType,
			"attributes": map[string]interface{}{
				"custom_rules": map[string]interface{}{},
			},
		},
	}

	// Add custom rules attributes if provided
	customRules := requestBody["data"].(map[string]interface{})["attributes"].(map[string]interface{})["custom_rules"].(map[string]interface{})
	
	if updateIacSettingsForOrgCustomRulesEnabled != nil {
		customRules["is_enabled"] = *updateIacSettingsForOrgCustomRulesEnabled
	}
	
	if updateIacSettingsForOrgCustomRulesOciURL != "" {
		customRules["oci_registry_url"] = updateIacSettingsForOrgCustomRulesOciURL
	}
	
	if updateIacSettingsForOrgCustomRulesOciTag != "" {
		customRules["oci_registry_tag"] = updateIacSettingsForOrgCustomRulesOciTag
	}
	
	if updateIacSettingsForOrgCustomRulesInheritFromParent != "" {
		customRules["inherit_from_parent"] = updateIacSettingsForOrgCustomRulesInheritFromParent
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleUpdateIacSettingsForOrgResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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