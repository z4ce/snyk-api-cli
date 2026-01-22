package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteSlackDefaultNotificationSettingsCmd represents the delete-slack-default-notification-settings command
var DeleteSlackDefaultNotificationSettingsCmd = &cobra.Command{
	Use:   "delete-slack-default-notification-settings [org_id] [bot_id]",
	Short: "Remove the given Slack App integration",
	Long: `Remove the given Slack App integration from the Snyk API.

This command removes a Slack App integration and its default notification settings
from a specific organization. Both organization ID and bot ID must be provided.

Examples:
  snyk-api-cli delete-slack-default-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli delete-slack-default-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteSlackDefaultNotificationSettings,
}

var (
	deleteSlackDefaultNotificationSettingsVerbose     bool
	deleteSlackDefaultNotificationSettingsSilent      bool
	deleteSlackDefaultNotificationSettingsIncludeResp bool
	deleteSlackDefaultNotificationSettingsUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteSlackDefaultNotificationSettingsCmd.Flags().BoolVarP(&deleteSlackDefaultNotificationSettingsVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteSlackDefaultNotificationSettingsCmd.Flags().BoolVarP(&deleteSlackDefaultNotificationSettingsSilent, "silent", "s", false, "Silent mode")
	DeleteSlackDefaultNotificationSettingsCmd.Flags().BoolVarP(&deleteSlackDefaultNotificationSettingsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteSlackDefaultNotificationSettingsCmd.Flags().StringVarP(&deleteSlackDefaultNotificationSettingsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteSlackDefaultNotificationSettings(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildDeleteSlackDefaultNotificationSettingsURL(endpoint, version, orgID, botID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteSlackDefaultNotificationSettingsVerbose,
		Silent:      deleteSlackDefaultNotificationSettingsSilent,
		IncludeResp: deleteSlackDefaultNotificationSettingsIncludeResp,
		UserAgent:   deleteSlackDefaultNotificationSettingsUserAgent,
	})
}

func buildDeleteSlackDefaultNotificationSettingsURL(endpoint, version, orgID, botID string) (string, error) {
	// Build base URL with org ID and bot ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s", endpoint, orgID, botID)

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
