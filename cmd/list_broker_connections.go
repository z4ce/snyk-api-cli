package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListBrokerConnectionsCmd represents the list-broker-connections command
var ListBrokerConnectionsCmd = &cobra.Command{
	Use:   "list-broker-connections [tenant_id] [install_id] [deployment_id]",
	Short: "List Broker connections",
	Long: `List Broker connections for a specific tenant, install ID, and deployment ID from the Snyk API.

This command retrieves a list of broker connections for the specified tenant, install ID, and deployment ID.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-broker-connections 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli list-broker-connections 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --limit 10
  snyk-api-cli list-broker-connections 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --starting-after abc123
  snyk-api-cli list-broker-connections 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --ending-before xyz789
  snyk-api-cli list-broker-connections 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runListBrokerConnections,
}

var (
	listBrokerConnectionsStartingAfter string
	listBrokerConnectionsEndingBefore  string
	listBrokerConnectionsLimit         int
	listBrokerConnectionsVerbose       bool
	listBrokerConnectionsSilent        bool
	listBrokerConnectionsIncludeResp   bool
	listBrokerConnectionsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListBrokerConnectionsCmd.Flags().StringVar(&listBrokerConnectionsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListBrokerConnectionsCmd.Flags().StringVar(&listBrokerConnectionsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListBrokerConnectionsCmd.Flags().IntVar(&listBrokerConnectionsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListBrokerConnectionsCmd.Flags().BoolVarP(&listBrokerConnectionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListBrokerConnectionsCmd.Flags().BoolVarP(&listBrokerConnectionsSilent, "silent", "s", false, "Silent mode")
	ListBrokerConnectionsCmd.Flags().BoolVarP(&listBrokerConnectionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListBrokerConnectionsCmd.Flags().StringVarP(&listBrokerConnectionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListBrokerConnections(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListBrokerConnectionsURL(endpoint, version, tenantID, installID, deploymentID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listBrokerConnectionsVerbose,
		Silent:      listBrokerConnectionsSilent,
		IncludeResp: listBrokerConnectionsIncludeResp,
		UserAgent:   listBrokerConnectionsUserAgent,
	})
}

func buildListBrokerConnectionsURL(endpoint, version, tenantID, installID, deploymentID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/connections", endpoint, tenantID, installID, deploymentID)

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
	if listBrokerConnectionsStartingAfter != "" {
		q.Set("starting_after", listBrokerConnectionsStartingAfter)
	}
	if listBrokerConnectionsEndingBefore != "" {
		q.Set("ending_before", listBrokerConnectionsEndingBefore)
	}
	if listBrokerConnectionsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listBrokerConnectionsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
