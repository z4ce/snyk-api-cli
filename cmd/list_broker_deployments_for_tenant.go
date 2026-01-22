package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListBrokerDeploymentsForTenantCmd represents the list-broker-deployments-for-tenant command
var ListBrokerDeploymentsForTenantCmd = &cobra.Command{
	Use:   "list-broker-deployments-for-tenant [tenant_id]",
	Short: "List Broker deployments for tenant",
	Long: `List Broker deployments for a specific tenant from the Snyk API.

This command retrieves a list of broker deployments for the specified tenant.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-broker-deployments-for-tenant 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-broker-deployments-for-tenant 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-broker-deployments-for-tenant 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli list-broker-deployments-for-tenant 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli list-broker-deployments-for-tenant 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListBrokerDeploymentsForTenant,
}

var (
	listBrokerDeploymentsForTenantStartingAfter string
	listBrokerDeploymentsForTenantEndingBefore  string
	listBrokerDeploymentsForTenantLimit         int
	listBrokerDeploymentsForTenantVerbose       bool
	listBrokerDeploymentsForTenantSilent        bool
	listBrokerDeploymentsForTenantIncludeResp   bool
	listBrokerDeploymentsForTenantUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListBrokerDeploymentsForTenantCmd.Flags().StringVar(&listBrokerDeploymentsForTenantStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListBrokerDeploymentsForTenantCmd.Flags().StringVar(&listBrokerDeploymentsForTenantEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListBrokerDeploymentsForTenantCmd.Flags().IntVar(&listBrokerDeploymentsForTenantLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListBrokerDeploymentsForTenantCmd.Flags().BoolVarP(&listBrokerDeploymentsForTenantVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListBrokerDeploymentsForTenantCmd.Flags().BoolVarP(&listBrokerDeploymentsForTenantSilent, "silent", "s", false, "Silent mode")
	ListBrokerDeploymentsForTenantCmd.Flags().BoolVarP(&listBrokerDeploymentsForTenantIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListBrokerDeploymentsForTenantCmd.Flags().StringVarP(&listBrokerDeploymentsForTenantUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListBrokerDeploymentsForTenant(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListBrokerDeploymentsForTenantURL(endpoint, version, tenantID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listBrokerDeploymentsForTenantVerbose,
		Silent:      listBrokerDeploymentsForTenantSilent,
		IncludeResp: listBrokerDeploymentsForTenantIncludeResp,
		UserAgent:   listBrokerDeploymentsForTenantUserAgent,
	})
}

func buildListBrokerDeploymentsForTenantURL(endpoint, version, tenantID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/deployments", endpoint, tenantID)

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
	if listBrokerDeploymentsForTenantStartingAfter != "" {
		q.Set("starting_after", listBrokerDeploymentsForTenantStartingAfter)
	}
	if listBrokerDeploymentsForTenantEndingBefore != "" {
		q.Set("ending_before", listBrokerDeploymentsForTenantEndingBefore)
	}
	if listBrokerDeploymentsForTenantLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listBrokerDeploymentsForTenantLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
