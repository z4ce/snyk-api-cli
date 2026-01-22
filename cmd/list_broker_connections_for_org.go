package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListBrokerConnectionsForOrgCmd represents the list-broker-connections-for-org command
var ListBrokerConnectionsForOrgCmd = &cobra.Command{
	Use:   "list-broker-connections-for-org [org_id]",
	Short: "List broker connections for an organization",
	Long: `List broker connections for a specific organization from the Snyk API.

This command retrieves a list of broker connections for the specified organization.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-broker-connections-for-org 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-broker-connections-for-org 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-broker-connections-for-org 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli list-broker-connections-for-org 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli list-broker-connections-for-org 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListBrokerConnectionsForOrg,
}

var (
	listBrokerConnectionsForOrgStartingAfter string
	listBrokerConnectionsForOrgEndingBefore  string
	listBrokerConnectionsForOrgLimit         int
	listBrokerConnectionsForOrgVerbose       bool
	listBrokerConnectionsForOrgSilent        bool
	listBrokerConnectionsForOrgIncludeResp   bool
	listBrokerConnectionsForOrgUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListBrokerConnectionsForOrgCmd.Flags().StringVar(&listBrokerConnectionsForOrgStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListBrokerConnectionsForOrgCmd.Flags().StringVar(&listBrokerConnectionsForOrgEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListBrokerConnectionsForOrgCmd.Flags().IntVar(&listBrokerConnectionsForOrgLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListBrokerConnectionsForOrgCmd.Flags().BoolVarP(&listBrokerConnectionsForOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListBrokerConnectionsForOrgCmd.Flags().BoolVarP(&listBrokerConnectionsForOrgSilent, "silent", "s", false, "Silent mode")
	ListBrokerConnectionsForOrgCmd.Flags().BoolVarP(&listBrokerConnectionsForOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListBrokerConnectionsForOrgCmd.Flags().StringVarP(&listBrokerConnectionsForOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListBrokerConnectionsForOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListBrokerConnectionsForOrgURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listBrokerConnectionsForOrgVerbose,
		Silent:      listBrokerConnectionsForOrgSilent,
		IncludeResp: listBrokerConnectionsForOrgIncludeResp,
		UserAgent:   listBrokerConnectionsForOrgUserAgent,
	})
}

func buildListBrokerConnectionsForOrgURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/brokers/connections", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional parameters if provided
	if listBrokerConnectionsForOrgStartingAfter != "" {
		q.Set("starting_after", listBrokerConnectionsForOrgStartingAfter)
	}
	if listBrokerConnectionsForOrgEndingBefore != "" {
		q.Set("ending_before", listBrokerConnectionsForOrgEndingBefore)
	}
	if listBrokerConnectionsForOrgLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listBrokerConnectionsForOrgLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
