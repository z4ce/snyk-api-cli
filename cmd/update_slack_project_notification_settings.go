package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateSlackProjectNotificationSettingsCmd represents the update-slack-project-notification-settings command
var UpdateSlackProjectNotificationSettingsCmd = &cobra.Command{
	Use:   "update-slack-project-notification-settings [org_id] [bot_id] [project_id]",
	Short: "Update Slack notification settings for a project",
	Long: `Update Slack notification settings for a project in the Snyk API.

This command updates existing Slack notification settings for a specific project
in an organization. The organization ID, bot ID, project ID, and settings ID must be provided,
along with the updated settings values.

Examples:
  snyk-api-cli update-slack-project-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11223344-5566-7788-9900-112233445566 --id 99887766-5544-3322-1100-998877665544 --is-active true --severity-threshold high --target-channel-id "C1234567890"
  snyk-api-cli update-slack-project-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11223344-5566-7788-9900-112233445566 --id 99887766-5544-3322-1100-998877665544 --is-active false --severity-threshold critical --target-channel-id "C0987654321" --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runUpdateSlackProjectNotificationSettings,
}

var (
	updateSlackProjectNotificationSettingsID                string
	updateSlackProjectNotificationSettingsIsActive          string
	updateSlackProjectNotificationSettingsSeverityThreshold string
	updateSlackProjectNotificationSettingsTargetChannelID   string
	updateSlackProjectNotificationSettingsVerbose           bool
	updateSlackProjectNotificationSettingsSilent            bool
	updateSlackProjectNotificationSettingsIncludeResp       bool
	updateSlackProjectNotificationSettingsUserAgent         string
)

func init() {
	// Add flags for request body attributes
	UpdateSlackProjectNotificationSettingsCmd.Flags().StringVar(&updateSlackProjectNotificationSettingsID, "id", "", "ID of the Slack project notification settings (required)")
	UpdateSlackProjectNotificationSettingsCmd.Flags().StringVar(&updateSlackProjectNotificationSettingsIsActive, "is-active", "", "Whether project settings are active: true or false (required)")
	UpdateSlackProjectNotificationSettingsCmd.Flags().StringVar(&updateSlackProjectNotificationSettingsSeverityThreshold, "severity-threshold", "", "Issue severity threshold: low, medium, high, or critical (required)")
	UpdateSlackProjectNotificationSettingsCmd.Flags().StringVar(&updateSlackProjectNotificationSettingsTargetChannelID, "target-channel-id", "", "Target Slack channel ID (required)")

	// Add standard flags like other commands
	UpdateSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&updateSlackProjectNotificationSettingsVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&updateSlackProjectNotificationSettingsSilent, "silent", "s", false, "Silent mode")
	UpdateSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&updateSlackProjectNotificationSettingsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateSlackProjectNotificationSettingsCmd.Flags().StringVarP(&updateSlackProjectNotificationSettingsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateSlackProjectNotificationSettingsCmd.MarkFlagRequired("id")
	UpdateSlackProjectNotificationSettingsCmd.MarkFlagRequired("is-active")
	UpdateSlackProjectNotificationSettingsCmd.MarkFlagRequired("severity-threshold")
	UpdateSlackProjectNotificationSettingsCmd.MarkFlagRequired("target-channel-id")
}

func runUpdateSlackProjectNotificationSettings(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	projectID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate severity threshold
	validSeverityThresholds := []string{"low", "medium", "high", "critical"}
	if !containsStringValue(validSeverityThresholds, updateSlackProjectNotificationSettingsSeverityThreshold) {
		return fmt.Errorf("invalid severity-threshold: %s. Must be one of: %s", updateSlackProjectNotificationSettingsSeverityThreshold, strings.Join(validSeverityThresholds, ", "))
	}

	// Validate is-active value
	if updateSlackProjectNotificationSettingsIsActive != "true" && updateSlackProjectNotificationSettingsIsActive != "false" {
		return fmt.Errorf("invalid is-active: %s. Must be 'true' or 'false'", updateSlackProjectNotificationSettingsIsActive)
	}

	// Build the URL
	fullURL, err := buildUpdateSlackProjectNotificationSettingsURL(endpoint, version, orgID, botID, projectID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateSlackProjectNotificationSettingsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateSlackProjectNotificationSettingsVerbose,
		Silent:      updateSlackProjectNotificationSettingsSilent,
		IncludeResp: updateSlackProjectNotificationSettingsIncludeResp,
		UserAgent:   updateSlackProjectNotificationSettingsUserAgent,
	})
}

func buildUpdateSlackProjectNotificationSettingsURL(endpoint, version, orgID, botID, projectID string) (string, error) {
	// Build base URL with organization ID, bot ID, and project ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s/projects/%s", endpoint, orgID, botID, projectID)

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

func buildUpdateSlackProjectNotificationSettingsRequestBody() (string, error) {
	// Parse is_active as boolean
	isActive, err := strconv.ParseBool(updateSlackProjectNotificationSettingsIsActive)
	if err != nil {
		return "", fmt.Errorf("failed to parse is-active as boolean: %w", err)
	}

	// Build attributes according to the API specification
	attributes := map[string]interface{}{
		"is_active":          isActive,
		"severity_threshold": updateSlackProjectNotificationSettingsSeverityThreshold,
		"target_channel_id":  updateSlackProjectNotificationSettingsTargetChannelID,
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"id":         updateSlackProjectNotificationSettingsID,
			"type":       "slack",
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

// Helper function to check if a slice contains a string (avoiding conflict with existing functions)
func containsStringValue(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
