package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetSlackDefaultNotificationSettingsCmd represents the get-slack-default-notification-settings command
var GetSlackDefaultNotificationSettingsCmd = &cobra.Command{
	Use:   "get-slack-default-notification-settings [org_id] [bot_id]",
	Short: "Get Slack integration default notification settings",
	Long: `Get Slack integration default notification settings from the Snyk API.

This command retrieves the default notification settings for a Slack integration
in a specific organization. Both organization ID and bot ID must be provided.

Examples:
  snyk-api-cli get-slack-default-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-slack-default-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-slack-default-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetSlackDefaultNotificationSettings,
}

var (
	getSlackDefaultNotificationSettingsVerbose     bool
	getSlackDefaultNotificationSettingsSilent      bool
	getSlackDefaultNotificationSettingsIncludeResp bool
	getSlackDefaultNotificationSettingsUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetSlackDefaultNotificationSettingsCmd.Flags().BoolVarP(&getSlackDefaultNotificationSettingsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetSlackDefaultNotificationSettingsCmd.Flags().BoolVarP(&getSlackDefaultNotificationSettingsSilent, "silent", "s", false, "Silent mode")
	GetSlackDefaultNotificationSettingsCmd.Flags().BoolVarP(&getSlackDefaultNotificationSettingsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetSlackDefaultNotificationSettingsCmd.Flags().StringVarP(&getSlackDefaultNotificationSettingsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetSlackDefaultNotificationSettings(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetSlackDefaultNotificationSettingsURL(endpoint, version, orgID, botID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getSlackDefaultNotificationSettingsVerbose,
		Silent:      getSlackDefaultNotificationSettingsSilent,
		IncludeResp: getSlackDefaultNotificationSettingsIncludeResp,
		UserAgent:   getSlackDefaultNotificationSettingsUserAgent,
	})
}

func buildGetSlackDefaultNotificationSettingsURL(endpoint, version, orgID, botID string) (string, error) {
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
