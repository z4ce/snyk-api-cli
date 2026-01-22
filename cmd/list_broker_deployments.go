package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListBrokerDeploymentsCmd represents the list-broker-deployments command
var ListBrokerDeploymentsCmd = &cobra.Command{
	Use:   "list-broker-deployments [tenant_id] [install_id]",
	Short: "List Broker deployments",
	Long: `List Broker deployments for a specific tenant and install from the Snyk API.

This command retrieves a list of broker deployments for the specified tenant and install ID.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-broker-deployments 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-broker-deployments 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 10
  snyk-api-cli list-broker-deployments 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --starting-after abc123
  snyk-api-cli list-broker-deployments 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --ending-before xyz789
  snyk-api-cli list-broker-deployments 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runListBrokerDeployments,
}

var (
	listBrokerDeploymentsStartingAfter string
	listBrokerDeploymentsEndingBefore  string
	listBrokerDeploymentsLimit         int
	listBrokerDeploymentsVerbose       bool
	listBrokerDeploymentsSilent        bool
	listBrokerDeploymentsIncludeResp   bool
	listBrokerDeploymentsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListBrokerDeploymentsCmd.Flags().StringVar(&listBrokerDeploymentsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListBrokerDeploymentsCmd.Flags().StringVar(&listBrokerDeploymentsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListBrokerDeploymentsCmd.Flags().IntVar(&listBrokerDeploymentsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListBrokerDeploymentsCmd.Flags().BoolVarP(&listBrokerDeploymentsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListBrokerDeploymentsCmd.Flags().BoolVarP(&listBrokerDeploymentsSilent, "silent", "s", false, "Silent mode")
	ListBrokerDeploymentsCmd.Flags().BoolVarP(&listBrokerDeploymentsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListBrokerDeploymentsCmd.Flags().StringVarP(&listBrokerDeploymentsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListBrokerDeployments(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListBrokerDeploymentsURL(endpoint, version, tenantID, installID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listBrokerDeploymentsVerbose,
		Silent:      listBrokerDeploymentsSilent,
		IncludeResp: listBrokerDeploymentsIncludeResp,
		UserAgent:   listBrokerDeploymentsUserAgent,
	})
}

func buildListBrokerDeploymentsURL(endpoint, version, tenantID, installID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments", endpoint, tenantID, installID)

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
	if listBrokerDeploymentsStartingAfter != "" {
		q.Set("starting_after", listBrokerDeploymentsStartingAfter)
	}
	if listBrokerDeploymentsEndingBefore != "" {
		q.Set("ending_before", listBrokerDeploymentsEndingBefore)
	}
	if listBrokerDeploymentsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listBrokerDeploymentsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
