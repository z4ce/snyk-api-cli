package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteSlackProjectNotificationSettingsCmd represents the delete-slack-project-notification-settings command
var DeleteSlackProjectNotificationSettingsCmd = &cobra.Command{
	Use:   "delete-slack-project-notification-settings [org_id] [bot_id] [project_id]",
	Short: "Remove Slack settings override for a project",
	Long: `Remove Slack settings override for a project from the Snyk API.

This command removes Slack notification settings override for a specific project
in an organization. The organization ID, bot ID, and project ID must be provided.

Examples:
  snyk-api-cli delete-slack-project-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11223344-5566-7788-9900-112233445566
  snyk-api-cli delete-slack-project-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11223344-5566-7788-9900-112233445566 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runDeleteSlackProjectNotificationSettings,
}

var (
	deleteSlackProjectNotificationSettingsVerbose     bool
	deleteSlackProjectNotificationSettingsSilent      bool
	deleteSlackProjectNotificationSettingsIncludeResp bool
	deleteSlackProjectNotificationSettingsUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&deleteSlackProjectNotificationSettingsVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&deleteSlackProjectNotificationSettingsSilent, "silent", "s", false, "Silent mode")
	DeleteSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&deleteSlackProjectNotificationSettingsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteSlackProjectNotificationSettingsCmd.Flags().StringVarP(&deleteSlackProjectNotificationSettingsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteSlackProjectNotificationSettings(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	projectID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildDeleteSlackProjectNotificationSettingsURL(endpoint, version, orgID, botID, projectID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteSlackProjectNotificationSettingsVerbose,
		Silent:      deleteSlackProjectNotificationSettingsSilent,
		IncludeResp: deleteSlackProjectNotificationSettingsIncludeResp,
		UserAgent:   deleteSlackProjectNotificationSettingsUserAgent,
	})
}

func buildDeleteSlackProjectNotificationSettingsURL(endpoint, version, orgID, botID, projectID string) (string, error) {
	// Build base URL with org ID, bot ID, and project ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s/projects/%s", endpoint, orgID, botID, projectID)

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
