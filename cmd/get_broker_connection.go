package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetBrokerConnectionCmd represents the get-broker-connection command
var GetBrokerConnectionCmd = &cobra.Command{
	Use:   "get-broker-connection [tenant_id] [install_id] [deployment_id] [connection_id]",
	Short: "Get Broker connection",
	Long: `Get Broker connection from the Snyk API.

This command retrieves details of a specific broker connection for a tenant, install ID, deployment ID, and connection ID.

Examples:
  snyk-api-cli get-broker-connection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222
  snyk-api-cli get-broker-connection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runGetBrokerConnection,
}

var (
	getBrokerConnectionVerbose     bool
	getBrokerConnectionSilent      bool
	getBrokerConnectionIncludeResp bool
	getBrokerConnectionUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetBrokerConnectionCmd.Flags().BoolVarP(&getBrokerConnectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetBrokerConnectionCmd.Flags().BoolVarP(&getBrokerConnectionSilent, "silent", "s", false, "Silent mode")
	GetBrokerConnectionCmd.Flags().BoolVarP(&getBrokerConnectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetBrokerConnectionCmd.Flags().StringVarP(&getBrokerConnectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetBrokerConnection(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	connectionID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetBrokerConnectionURL(endpoint, version, tenantID, installID, deploymentID, connectionID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getBrokerConnectionVerbose,
		Silent:      getBrokerConnectionSilent,
		IncludeResp: getBrokerConnectionIncludeResp,
		UserAgent:   getBrokerConnectionUserAgent,
	})
}

func buildGetBrokerConnectionURL(endpoint, version, tenantID, installID, deploymentID, connectionID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/connections/%s", endpoint, tenantID, installID, deploymentID, connectionID)

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
