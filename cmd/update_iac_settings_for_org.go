package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

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
	updateIacSettingsForOrgVerbose                      bool
	updateIacSettingsForOrgSilent                       bool
	updateIacSettingsForOrgIncludeResp                  bool
	updateIacSettingsForOrgUserAgent                    string
	updateIacSettingsForOrgDataType                     string
	updateIacSettingsForOrgCustomRulesEnabled           *bool
	updateIacSettingsForOrgCustomRulesOciURL            string
	updateIacSettingsForOrgCustomRulesOciTag            string
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

	// Build request body
	requestBody, err := buildUpdateIacSettingsForOrgRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateIacSettingsForOrgVerbose,
		Silent:      updateIacSettingsForOrgSilent,
		IncludeResp: updateIacSettingsForOrgIncludeResp,
		UserAgent:   updateIacSettingsForOrgUserAgent,
	})
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
