package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListChannelsCmd represents the list-channels command
var ListChannelsCmd = &cobra.Command{
	Use:   "list-channels [org_id] [tenant_id]",
	Short: "Get a list of Slack channels",
	Long: `Get a list of Slack channels from the Snyk API.

This command retrieves a list of available Slack channels for a specific organization
and tenant. Both organization ID and tenant ID must be provided.

Note: Currently only possible to page forwards through this collection.

Examples:
  snyk-api-cli list-channels 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-channels 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 50
  snyk-api-cli list-channels 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --starting-after "cursor123" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runListChannels,
}

var (
	listChannelsStartingAfter string
	listChannelsEndingBefore  string
	listChannelsLimit         int
	listChannelsVerbose       bool
	listChannelsSilent        bool
	listChannelsIncludeResp   bool
	listChannelsUserAgent     string
)

func init() {
	// Add pagination flags
	ListChannelsCmd.Flags().StringVar(&listChannelsStartingAfter, "starting-after", "", "Cursor for pagination - results after this cursor")
	ListChannelsCmd.Flags().StringVar(&listChannelsEndingBefore, "ending-before", "", "Cursor for pagination - results before this cursor")
	ListChannelsCmd.Flags().IntVar(&listChannelsLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	ListChannelsCmd.Flags().BoolVarP(&listChannelsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListChannelsCmd.Flags().BoolVarP(&listChannelsSilent, "silent", "s", false, "Silent mode")
	ListChannelsCmd.Flags().BoolVarP(&listChannelsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListChannelsCmd.Flags().StringVarP(&listChannelsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListChannels(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	tenantID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListChannelsURL(endpoint, version, orgID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listChannelsVerbose,
		Silent:      listChannelsSilent,
		IncludeResp: listChannelsIncludeResp,
		UserAgent:   listChannelsUserAgent,
	})
}

func buildListChannelsURL(endpoint, version, orgID, tenantID string) (string, error) {
	// Build base URL with org ID and tenant ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s/channels", endpoint, orgID, tenantID)

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
	if listChannelsStartingAfter != "" {
		q.Set("starting_after", listChannelsStartingAfter)
	}
	if listChannelsEndingBefore != "" {
		q.Set("ending_before", listChannelsEndingBefore)
	}
	if listChannelsLimit > 0 {
		q.Set("limit", strconv.Itoa(listChannelsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
