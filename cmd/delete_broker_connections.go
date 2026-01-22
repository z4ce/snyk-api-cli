package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteBrokerConnectionsCmd represents the delete-broker-connections command
var DeleteBrokerConnectionsCmd = &cobra.Command{
	Use:   "delete-broker-connections [tenant_id] [install_id] [deployment_id]",
	Short: "Deletes Broker connections",
	Long: `Deletes all existing Broker connections for a deployment from the Snyk API.

This command deletes all broker connections for a specific tenant, install ID, and deployment ID.

Examples:
  snyk-api-cli delete-broker-connections 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli delete-broker-connections 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runDeleteBrokerConnections,
}

var (
	deleteBrokerConnectionsVerbose     bool
	deleteBrokerConnectionsSilent      bool
	deleteBrokerConnectionsIncludeResp bool
	deleteBrokerConnectionsUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteBrokerConnectionsCmd.Flags().BoolVarP(&deleteBrokerConnectionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteBrokerConnectionsCmd.Flags().BoolVarP(&deleteBrokerConnectionsSilent, "silent", "s", false, "Silent mode")
	DeleteBrokerConnectionsCmd.Flags().BoolVarP(&deleteBrokerConnectionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteBrokerConnectionsCmd.Flags().StringVarP(&deleteBrokerConnectionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteBrokerConnections(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildDeleteBrokerConnectionsURL(endpoint, version, tenantID, installID, deploymentID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteBrokerConnectionsVerbose,
		Silent:      deleteBrokerConnectionsSilent,
		IncludeResp: deleteBrokerConnectionsIncludeResp,
		UserAgent:   deleteBrokerConnectionsUserAgent,
	})
}

func buildDeleteBrokerConnectionsURL(endpoint, version, tenantID, installID, deploymentID string) (string, error) {
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
