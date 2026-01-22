package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateSlackProjectNotificationSettingsCmd represents the create-slack-project-notification-settings command
var CreateSlackProjectNotificationSettingsCmd = &cobra.Command{
	Use:   "create-slack-project-notification-settings [org_id] [bot_id] [project_id]",
	Short: "Create a new Slack settings override for a given project",
	Long: `Create a new Slack settings override for a given project in the Snyk API.

This command creates Slack notification settings override for a specific project
in an organization. The organization ID, bot ID, project ID, severity threshold, 
and target channel ID must be provided.

Examples:
  snyk-api-cli create-slack-project-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11223344-5566-7788-9900-112233445566 --severity-threshold high --target-channel-id "C1234567890"
  snyk-api-cli create-slack-project-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11223344-5566-7788-9900-112233445566 --severity-threshold critical --target-channel-id "C0987654321" --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runCreateSlackProjectNotificationSettings,
}

var (
	createSlackProjectNotificationSettingsSeverityThreshold string
	createSlackProjectNotificationSettingsTargetChannelID   string
	createSlackProjectNotificationSettingsVerbose           bool
	createSlackProjectNotificationSettingsSilent            bool
	createSlackProjectNotificationSettingsIncludeResp       bool
	createSlackProjectNotificationSettingsUserAgent         string
)

func init() {
	// Add flags for request body attributes
	CreateSlackProjectNotificationSettingsCmd.Flags().StringVar(&createSlackProjectNotificationSettingsSeverityThreshold, "severity-threshold", "", "Issue severity threshold: low, medium, high, or critical (required)")
	CreateSlackProjectNotificationSettingsCmd.Flags().StringVar(&createSlackProjectNotificationSettingsTargetChannelID, "target-channel-id", "", "Target Slack channel ID (required)")

	// Add standard flags like other commands
	CreateSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&createSlackProjectNotificationSettingsVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&createSlackProjectNotificationSettingsSilent, "silent", "s", false, "Silent mode")
	CreateSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&createSlackProjectNotificationSettingsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateSlackProjectNotificationSettingsCmd.Flags().StringVarP(&createSlackProjectNotificationSettingsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateSlackProjectNotificationSettingsCmd.MarkFlagRequired("severity-threshold")
	CreateSlackProjectNotificationSettingsCmd.MarkFlagRequired("target-channel-id")
}

func runCreateSlackProjectNotificationSettings(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	projectID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate severity threshold
	validSeverityThresholds := []string{"low", "medium", "high", "critical"}
	if !containsStringItem(validSeverityThresholds, createSlackProjectNotificationSettingsSeverityThreshold) {
		return fmt.Errorf("invalid severity-threshold: %s. Must be one of: %s", createSlackProjectNotificationSettingsSeverityThreshold, strings.Join(validSeverityThresholds, ", "))
	}

	// Build the URL
	fullURL, err := buildCreateSlackProjectNotificationSettingsURL(endpoint, version, orgID, botID, projectID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateSlackProjectNotificationSettingsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createSlackProjectNotificationSettingsVerbose,
		Silent:      createSlackProjectNotificationSettingsSilent,
		IncludeResp: createSlackProjectNotificationSettingsIncludeResp,
		UserAgent:   createSlackProjectNotificationSettingsUserAgent,
	})
}

func buildCreateSlackProjectNotificationSettingsURL(endpoint, version, orgID, botID, projectID string) (string, error) {
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

func buildCreateSlackProjectNotificationSettingsRequestBody() (string, error) {
	// Build attributes according to the API specification
	attributes := map[string]interface{}{
		"severity_threshold": createSlackProjectNotificationSettingsSeverityThreshold,
		"target_channel_id":  createSlackProjectNotificationSettingsTargetChannelID,
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
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

// Helper function to check if a slice contains a string (avoiding conflict with existing contains function)
func containsStringItem(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
