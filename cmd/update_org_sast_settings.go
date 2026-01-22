package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateOrgSastSettingsCmd represents the update-org-sast-settings command
var UpdateOrgSastSettingsCmd = &cobra.Command{
	Use:   "update-org-sast-settings [org_id]",
	Short: "Update SAST settings for an organization",
	Long: `Update SAST settings for an organization using the Snyk API.

This command updates the SAST (Static Application Security Testing) settings for a specific organization by its ID.
The organization ID must be provided as a required argument.

Required permissions: View Organization (org.read), Edit Organization (org.edit)

Examples:
  snyk-api-cli update-org-sast-settings 12345678-1234-1234-1234-123456789012 --type sast_settings --sast-enabled=true
  snyk-api-cli update-org-sast-settings 12345678-1234-1234-1234-123456789012 --type sast_settings --sast-enabled=false --verbose
  snyk-api-cli update-org-sast-settings 12345678-1234-1234-1234-123456789012 --type sast_settings --sast-enabled=true --id 12345678-1234-1234-1234-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runUpdateOrgSastSettings,
}

var (
	updateOrgSastSettingsVerbose     bool
	updateOrgSastSettingsSilent      bool
	updateOrgSastSettingsIncludeResp bool
	updateOrgSastSettingsUserAgent   string
	updateOrgSastSettingsDataType    string
	updateOrgSastSettingsID          string
	updateOrgSastSettingsSastEnabled *bool
)

func init() {
	// Add standard flags like other commands
	UpdateOrgSastSettingsCmd.Flags().BoolVarP(&updateOrgSastSettingsVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateOrgSastSettingsCmd.Flags().BoolVarP(&updateOrgSastSettingsSilent, "silent", "s", false, "Silent mode")
	UpdateOrgSastSettingsCmd.Flags().BoolVarP(&updateOrgSastSettingsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateOrgSastSettingsCmd.Flags().StringVarP(&updateOrgSastSettingsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Add request body flags
	UpdateOrgSastSettingsCmd.Flags().StringVar(&updateOrgSastSettingsDataType, "type", "sast_settings", "The type field for the data object")
	UpdateOrgSastSettingsCmd.Flags().StringVar(&updateOrgSastSettingsID, "id", "", "The ID field for the data object (UUID)")
	
	// SAST settings flag
	var sastEnabled bool
	UpdateOrgSastSettingsCmd.Flags().BoolVar(&sastEnabled, "sast-enabled", false, "Enable or disable SAST")
	
	// Handle the boolean pointer for SAST enabled
	UpdateOrgSastSettingsCmd.Flags().Lookup("sast-enabled").Changed = false
	UpdateOrgSastSettingsCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("sast-enabled") {
			updateOrgSastSettingsSastEnabled = &sastEnabled
		}
		return nil
	}
}

func runUpdateOrgSastSettings(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateOrgSastSettingsURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateOrgSastSettingsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateOrgSastSettingsVerbose,
		Silent:      updateOrgSastSettingsSilent,
		IncludeResp: updateOrgSastSettingsIncludeResp,
		UserAgent:   updateOrgSastSettingsUserAgent,
	})
}

func buildUpdateOrgSastSettingsURL(endpoint, version, orgID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/settings/sast", endpoint, orgID)

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

func buildUpdateOrgSastSettingsRequestBody() (string, error) {
	// Build the request body according to the API specification
	data := map[string]interface{}{
		"type": updateOrgSastSettingsDataType,
	}

	// Add ID if provided
	if updateOrgSastSettingsID != "" {
		data["id"] = updateOrgSastSettingsID
	}

	// Build attributes object
	attributes := make(map[string]interface{})
	
	if updateOrgSastSettingsSastEnabled != nil {
		attributes["sast_enabled"] = *updateOrgSastSettingsSastEnabled
	}

	// Add attributes if any were provided
	if len(attributes) > 0 {
		data["attributes"] = attributes
	}

	requestBody := map[string]interface{}{
		"data": data,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
