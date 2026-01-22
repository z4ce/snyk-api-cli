package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteBrokerConnectionCmd represents the delete-broker-connection command
var DeleteBrokerConnectionCmd = &cobra.Command{
	Use:   "delete-broker-connection [tenant_id] [install_id] [deployment_id] [connection_id]",
	Short: "Deletes Broker connection",
	Long: `Deletes Broker connection from the Snyk API.

This command deletes an existing broker connection for a specific tenant, install ID, deployment ID, and connection ID.

Examples:
  snyk-api-cli delete-broker-connection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222
  snyk-api-cli delete-broker-connection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runDeleteBrokerConnection,
}

var (
	deleteBrokerConnectionVerbose     bool
	deleteBrokerConnectionSilent      bool
	deleteBrokerConnectionIncludeResp bool
	deleteBrokerConnectionUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteBrokerConnectionCmd.Flags().BoolVarP(&deleteBrokerConnectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteBrokerConnectionCmd.Flags().BoolVarP(&deleteBrokerConnectionSilent, "silent", "s", false, "Silent mode")
	DeleteBrokerConnectionCmd.Flags().BoolVarP(&deleteBrokerConnectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteBrokerConnectionCmd.Flags().StringVarP(&deleteBrokerConnectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteBrokerConnection(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	connectionID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildDeleteBrokerConnectionURL(endpoint, version, tenantID, installID, deploymentID, connectionID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteBrokerConnectionVerbose,
		Silent:      deleteBrokerConnectionSilent,
		IncludeResp: deleteBrokerConnectionIncludeResp,
		UserAgent:   deleteBrokerConnectionUserAgent,
	})
}

func buildDeleteBrokerConnectionURL(endpoint, version, tenantID, installID, deploymentID, connectionID string) (string, error) {
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
