package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetChannelNameByIdCmd represents the get-channel-name-by-id command
var GetChannelNameByIdCmd = &cobra.Command{
	Use:   "get-channel-name-by-id [org_id] [tenant_id] [channel_id]",
	Short: "Get Slack Channel name by Slack Channel ID",
	Long: `Get Slack Channel name by Slack Channel ID from the Snyk API.

This command retrieves the name and type of a specific Slack channel by its ID
for a given organization and tenant. The organization ID, tenant ID, and channel ID 
must all be provided.

Examples:
  snyk-api-cli get-channel-name-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 C1234567890
  snyk-api-cli get-channel-name-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 C0987654321 --verbose
  snyk-api-cli get-channel-name-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 C1122334455 --include`,
	Args: cobra.ExactArgs(3),
	RunE: runGetChannelNameById,
}

var (
	getChannelNameByIdVerbose     bool
	getChannelNameByIdSilent      bool
	getChannelNameByIdIncludeResp bool
	getChannelNameByIdUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetChannelNameByIdCmd.Flags().BoolVarP(&getChannelNameByIdVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetChannelNameByIdCmd.Flags().BoolVarP(&getChannelNameByIdSilent, "silent", "s", false, "Silent mode")
	GetChannelNameByIdCmd.Flags().BoolVarP(&getChannelNameByIdIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetChannelNameByIdCmd.Flags().StringVarP(&getChannelNameByIdUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetChannelNameById(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	tenantID := args[1]
	channelID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetChannelNameByIdURL(endpoint, version, orgID, tenantID, channelID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getChannelNameByIdVerbose,
		Silent:      getChannelNameByIdSilent,
		IncludeResp: getChannelNameByIdIncludeResp,
		UserAgent:   getChannelNameByIdUserAgent,
	})
}

func buildGetChannelNameByIdURL(endpoint, version, orgID, tenantID, channelID string) (string, error) {
	// Build base URL with org ID, tenant ID, and channel ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s/channels/%s", endpoint, orgID, tenantID, channelID)

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
