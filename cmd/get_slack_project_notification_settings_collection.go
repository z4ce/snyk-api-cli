package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetSlackProjectNotificationSettingsCollectionCmd represents the get-slack-project-notification-settings-collection command
var GetSlackProjectNotificationSettingsCollectionCmd = &cobra.Command{
	Use:   "get-slack-project-notification-settings-collection [org_id] [bot_id]",
	Short: "Slack notification settings overrides for projects",
	Long: `Get Slack notification settings overrides for projects from the Snyk API.

This command retrieves a collection of Slack notification settings overrides for projects
in a specific organization. Both organization ID and bot ID must be provided.

Examples:
  snyk-api-cli get-slack-project-notification-settings-collection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-slack-project-notification-settings-collection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 50
  snyk-api-cli get-slack-project-notification-settings-collection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --starting-after "cursor123" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runGetSlackProjectNotificationSettingsCollection,
}

var (
	getSlackProjectNotificationSettingsCollectionStartingAfter string
	getSlackProjectNotificationSettingsCollectionEndingBefore  string
	getSlackProjectNotificationSettingsCollectionLimit         int
	getSlackProjectNotificationSettingsCollectionVerbose       bool
	getSlackProjectNotificationSettingsCollectionSilent        bool
	getSlackProjectNotificationSettingsCollectionIncludeResp   bool
	getSlackProjectNotificationSettingsCollectionUserAgent     string
)

func init() {
	// Add pagination flags
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().StringVar(&getSlackProjectNotificationSettingsCollectionStartingAfter, "starting-after", "", "Cursor for pagination - results after this cursor")
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().StringVar(&getSlackProjectNotificationSettingsCollectionEndingBefore, "ending-before", "", "Cursor for pagination - results before this cursor")
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().IntVar(&getSlackProjectNotificationSettingsCollectionLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().BoolVarP(&getSlackProjectNotificationSettingsCollectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().BoolVarP(&getSlackProjectNotificationSettingsCollectionSilent, "silent", "s", false, "Silent mode")
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().BoolVarP(&getSlackProjectNotificationSettingsCollectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().StringVarP(&getSlackProjectNotificationSettingsCollectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetSlackProjectNotificationSettingsCollection(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetSlackProjectNotificationSettingsCollectionURL(endpoint, version, orgID, botID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getSlackProjectNotificationSettingsCollectionVerbose,
		Silent:      getSlackProjectNotificationSettingsCollectionSilent,
		IncludeResp: getSlackProjectNotificationSettingsCollectionIncludeResp,
		UserAgent:   getSlackProjectNotificationSettingsCollectionUserAgent,
	})
}

func buildGetSlackProjectNotificationSettingsCollectionURL(endpoint, version, orgID, botID string) (string, error) {
	// Build base URL with org ID and bot ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s/projects", endpoint, orgID, botID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add pagination parameters if specified
	if getSlackProjectNotificationSettingsCollectionStartingAfter != "" {
		q.Set("starting_after", getSlackProjectNotificationSettingsCollectionStartingAfter)
	}
	if getSlackProjectNotificationSettingsCollectionEndingBefore != "" {
		q.Set("ending_before", getSlackProjectNotificationSettingsCollectionEndingBefore)
	}
	if getSlackProjectNotificationSettingsCollectionLimit > 0 {
		q.Set("limit", strconv.Itoa(getSlackProjectNotificationSettingsCollectionLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
