package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteBrokerDeploymentCmd represents the delete-broker-deployment command
var DeleteBrokerDeploymentCmd = &cobra.Command{
	Use:   "delete-broker-deployment [tenant_id] [install_id] [deployment_id]",
	Short: "Deletes Broker deployment",
	Long: `Deletes Broker deployment from the Snyk API.

This command deletes an existing broker deployment for a specific tenant, install ID, and deployment ID.

Examples:
  snyk-api-cli delete-broker-deployment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli delete-broker-deployment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runDeleteBrokerDeployment,
}

var (
	deleteBrokerDeploymentVerbose     bool
	deleteBrokerDeploymentSilent      bool
	deleteBrokerDeploymentIncludeResp bool
	deleteBrokerDeploymentUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteBrokerDeploymentCmd.Flags().BoolVarP(&deleteBrokerDeploymentVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteBrokerDeploymentCmd.Flags().BoolVarP(&deleteBrokerDeploymentSilent, "silent", "s", false, "Silent mode")
	DeleteBrokerDeploymentCmd.Flags().BoolVarP(&deleteBrokerDeploymentIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteBrokerDeploymentCmd.Flags().StringVarP(&deleteBrokerDeploymentUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteBrokerDeployment(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildDeleteBrokerDeploymentURL(endpoint, version, tenantID, installID, deploymentID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteBrokerDeploymentVerbose,
		Silent:      deleteBrokerDeploymentSilent,
		IncludeResp: deleteBrokerDeploymentIncludeResp,
		UserAgent:   deleteBrokerDeploymentUserAgent,
	})
}

func buildDeleteBrokerDeploymentURL(endpoint, version, tenantID, installID, deploymentID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s", endpoint, tenantID, installID, deploymentID)

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
