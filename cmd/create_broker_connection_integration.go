package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateBrokerConnectionIntegrationCmd represents the create-broker-connection-integration command
var CreateBrokerConnectionIntegrationCmd = &cobra.Command{
	Use:   "create-broker-connection-integration [tenant_id] [connection_id] [org_id]",
	Short: "Creates Broker connection Integration Configuration",
	Long: `Creates Broker connection Integration Configuration from the Snyk API.

This command creates a new integration configuration for a specific broker connection within a tenant and organization.
The integration_id and type must be provided in the request data.

Examples:
  snyk-api-cli create-broker-connection-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"integration_id":"integration-uuid","type":"broker_integration"}}'
  snyk-api-cli create-broker-connection-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"integration_id":"integration-uuid","type":"broker_integration"}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runCreateBrokerConnectionIntegration,
}

var (
	createBrokerConnectionIntegrationData        string
	createBrokerConnectionIntegrationVerbose     bool
	createBrokerConnectionIntegrationSilent      bool
	createBrokerConnectionIntegrationIncludeResp bool
	createBrokerConnectionIntegrationUserAgent   string
)

func init() {
	// Add flags for request data
	CreateBrokerConnectionIntegrationCmd.Flags().StringVarP(&createBrokerConnectionIntegrationData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	CreateBrokerConnectionIntegrationCmd.Flags().BoolVarP(&createBrokerConnectionIntegrationVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateBrokerConnectionIntegrationCmd.Flags().BoolVarP(&createBrokerConnectionIntegrationSilent, "silent", "s", false, "Silent mode")
	CreateBrokerConnectionIntegrationCmd.Flags().BoolVarP(&createBrokerConnectionIntegrationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateBrokerConnectionIntegrationCmd.Flags().StringVarP(&createBrokerConnectionIntegrationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	CreateBrokerConnectionIntegrationCmd.MarkFlagRequired("data")
}

func runCreateBrokerConnectionIntegration(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	connectionID := args[1]
	orgID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildCreateBrokerConnectionIntegrationURL(endpoint, version, tenantID, connectionID, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        createBrokerConnectionIntegrationData,
		ContentType: "application/vnd.api+json",
		Verbose:     createBrokerConnectionIntegrationVerbose,
		Silent:      createBrokerConnectionIntegrationSilent,
		IncludeResp: createBrokerConnectionIntegrationIncludeResp,
		UserAgent:   createBrokerConnectionIntegrationUserAgent,
	})
}

func buildCreateBrokerConnectionIntegrationURL(endpoint, version, tenantID, connectionID, orgID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/connections/%s/orgs/%s/integration", endpoint, tenantID, connectionID, orgID)

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
