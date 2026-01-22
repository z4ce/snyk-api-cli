package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateBrokerConnectionCmd represents the update-broker-connection command
var UpdateBrokerConnectionCmd = &cobra.Command{
	Use:   "update-broker-connection [tenant_id] [install_id] [deployment_id] [connection_id]",
	Short: "Updates Broker connection",
	Long: `Updates Broker connection from the Snyk API.

This command updates an existing broker connection for a specific tenant, install ID, deployment ID, and connection ID.
The request data should be provided in JSON format.

Examples:
  snyk-api-cli update-broker-connection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --data '{"data":{"type":"broker_connection","id":"22222222-2222-2222-2222-222222222222","attributes":{}}}'
  snyk-api-cli update-broker-connection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --data '{"data":{"type":"broker_connection","id":"22222222-2222-2222-2222-222222222222","attributes":{}}}' --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runUpdateBrokerConnection,
}

var (
	updateBrokerConnectionData        string
	updateBrokerConnectionVerbose     bool
	updateBrokerConnectionSilent      bool
	updateBrokerConnectionIncludeResp bool
	updateBrokerConnectionUserAgent   string
)

func init() {
	// Add flags for request data
	UpdateBrokerConnectionCmd.Flags().StringVarP(&updateBrokerConnectionData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	UpdateBrokerConnectionCmd.Flags().BoolVarP(&updateBrokerConnectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateBrokerConnectionCmd.Flags().BoolVarP(&updateBrokerConnectionSilent, "silent", "s", false, "Silent mode")
	UpdateBrokerConnectionCmd.Flags().BoolVarP(&updateBrokerConnectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateBrokerConnectionCmd.Flags().StringVarP(&updateBrokerConnectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	UpdateBrokerConnectionCmd.MarkFlagRequired("data")
}

func runUpdateBrokerConnection(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	connectionID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildUpdateBrokerConnectionURL(endpoint, version, tenantID, installID, deploymentID, connectionID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        updateBrokerConnectionData,
		Verbose:     updateBrokerConnectionVerbose,
		Silent:      updateBrokerConnectionSilent,
		IncludeResp: updateBrokerConnectionIncludeResp,
		UserAgent:   updateBrokerConnectionUserAgent,
	})
}

func buildUpdateBrokerConnectionURL(endpoint, version, tenantID, installID, deploymentID, connectionID string) (string, error) {
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
