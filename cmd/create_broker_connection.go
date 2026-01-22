package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateBrokerConnectionCmd represents the create-broker-connection command
var CreateBrokerConnectionCmd = &cobra.Command{
	Use:   "create-broker-connection [tenant_id] [install_id] [deployment_id]",
	Short: "Creates Broker connection",
	Long: `Creates Broker connection from the Snyk API.

This command creates a new broker connection for a specific tenant, install ID, and deployment ID.
The request data should be provided in JSON format.

Examples:
  snyk-api-cli create-broker-connection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"type":"broker_connection","attributes":{}}}'
  snyk-api-cli create-broker-connection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"type":"broker_connection","attributes":{}}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runCreateBrokerConnection,
}

var (
	createBrokerConnectionData        string
	createBrokerConnectionVerbose     bool
	createBrokerConnectionSilent      bool
	createBrokerConnectionIncludeResp bool
	createBrokerConnectionUserAgent   string
)

func init() {
	// Add flags for request data
	CreateBrokerConnectionCmd.Flags().StringVarP(&createBrokerConnectionData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	CreateBrokerConnectionCmd.Flags().BoolVarP(&createBrokerConnectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateBrokerConnectionCmd.Flags().BoolVarP(&createBrokerConnectionSilent, "silent", "s", false, "Silent mode")
	CreateBrokerConnectionCmd.Flags().BoolVarP(&createBrokerConnectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateBrokerConnectionCmd.Flags().StringVarP(&createBrokerConnectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	CreateBrokerConnectionCmd.MarkFlagRequired("data")
}

func runCreateBrokerConnection(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildCreateBrokerConnectionURL(endpoint, version, tenantID, installID, deploymentID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        createBrokerConnectionData,
		ContentType: "application/vnd.api+json",
		Verbose:     createBrokerConnectionVerbose,
		Silent:      createBrokerConnectionSilent,
		IncludeResp: createBrokerConnectionIncludeResp,
		UserAgent:   createBrokerConnectionUserAgent,
	})
}

func buildCreateBrokerConnectionURL(endpoint, version, tenantID, installID, deploymentID string) (string, error) {
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

	u.RawQuery = q.Encode()
	return u.String(), nil
}
