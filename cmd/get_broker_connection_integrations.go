package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetBrokerConnectionIntegrationsCmd represents the get-broker-connection-integrations command
var GetBrokerConnectionIntegrationsCmd = &cobra.Command{
	Use:   "get-broker-connection-integrations [tenant_id] [connection_id]",
	Short: "Get Integrations using the current Broker connection",
	Long: `Get Integrations using the current Broker connection from the Snyk API.

This command retrieves a list of integrations for a specific broker connection within a tenant.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli get-broker-connection-integrations 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-broker-connection-integrations 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 10
  snyk-api-cli get-broker-connection-integrations 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --starting-after abc123
  snyk-api-cli get-broker-connection-integrations 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --ending-before xyz789
  snyk-api-cli get-broker-connection-integrations 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runGetBrokerConnectionIntegrations,
}

var (
	getBrokerConnectionIntegrationsStartingAfter string
	getBrokerConnectionIntegrationsEndingBefore  string
	getBrokerConnectionIntegrationsLimit         int
	getBrokerConnectionIntegrationsVerbose       bool
	getBrokerConnectionIntegrationsSilent        bool
	getBrokerConnectionIntegrationsIncludeResp   bool
	getBrokerConnectionIntegrationsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetBrokerConnectionIntegrationsCmd.Flags().StringVar(&getBrokerConnectionIntegrationsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetBrokerConnectionIntegrationsCmd.Flags().StringVar(&getBrokerConnectionIntegrationsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	GetBrokerConnectionIntegrationsCmd.Flags().IntVar(&getBrokerConnectionIntegrationsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	GetBrokerConnectionIntegrationsCmd.Flags().BoolVarP(&getBrokerConnectionIntegrationsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetBrokerConnectionIntegrationsCmd.Flags().BoolVarP(&getBrokerConnectionIntegrationsSilent, "silent", "s", false, "Silent mode")
	GetBrokerConnectionIntegrationsCmd.Flags().BoolVarP(&getBrokerConnectionIntegrationsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetBrokerConnectionIntegrationsCmd.Flags().StringVarP(&getBrokerConnectionIntegrationsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetBrokerConnectionIntegrations(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	connectionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetBrokerConnectionIntegrationsURL(endpoint, version, tenantID, connectionID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getBrokerConnectionIntegrationsVerbose,
		Silent:      getBrokerConnectionIntegrationsSilent,
		IncludeResp: getBrokerConnectionIntegrationsIncludeResp,
		UserAgent:   getBrokerConnectionIntegrationsUserAgent,
	})
}

func buildGetBrokerConnectionIntegrationsURL(endpoint, version, tenantID, connectionID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/connections/%s/integrations", endpoint, tenantID, connectionID)

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
	if getBrokerConnectionIntegrationsStartingAfter != "" {
		q.Set("starting_after", getBrokerConnectionIntegrationsStartingAfter)
	}
	if getBrokerConnectionIntegrationsEndingBefore != "" {
		q.Set("ending_before", getBrokerConnectionIntegrationsEndingBefore)
	}
	if getBrokerConnectionIntegrationsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getBrokerConnectionIntegrationsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
