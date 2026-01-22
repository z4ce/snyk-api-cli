package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateBrokerDeploymentCmd represents the update-broker-deployment command
var UpdateBrokerDeploymentCmd = &cobra.Command{
	Use:   "update-broker-deployment [tenant_id] [install_id] [deployment_id]",
	Short: "Updates Broker deployment",
	Long: `Updates Broker deployment from the Snyk API.

This command updates an existing broker deployment for a specific tenant, install ID, and deployment ID.
The request data should be provided in JSON format.

Examples:
  snyk-api-cli update-broker-deployment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"type":"broker_deployment","id":"11111111-1111-1111-1111-111111111111","attributes":{"broker_app_installed_in_org_id":"22222222-2222-2222-2222-222222222222","install_id":"87654321-4321-4321-4321-210987654321","metadata":{}}}}'
  snyk-api-cli update-broker-deployment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"type":"broker_deployment","id":"11111111-1111-1111-1111-111111111111","attributes":{"broker_app_installed_in_org_id":"22222222-2222-2222-2222-222222222222","install_id":"87654321-4321-4321-4321-210987654321","metadata":{}}}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runUpdateBrokerDeployment,
}

var (
	updateBrokerDeploymentData        string
	updateBrokerDeploymentVerbose     bool
	updateBrokerDeploymentSilent      bool
	updateBrokerDeploymentIncludeResp bool
	updateBrokerDeploymentUserAgent   string
)

func init() {
	// Add flags for request data
	UpdateBrokerDeploymentCmd.Flags().StringVarP(&updateBrokerDeploymentData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	UpdateBrokerDeploymentCmd.Flags().BoolVarP(&updateBrokerDeploymentVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateBrokerDeploymentCmd.Flags().BoolVarP(&updateBrokerDeploymentSilent, "silent", "s", false, "Silent mode")
	UpdateBrokerDeploymentCmd.Flags().BoolVarP(&updateBrokerDeploymentIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateBrokerDeploymentCmd.Flags().StringVarP(&updateBrokerDeploymentUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	UpdateBrokerDeploymentCmd.MarkFlagRequired("data")
}

func runUpdateBrokerDeployment(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildUpdateBrokerDeploymentURL(endpoint, version, tenantID, installID, deploymentID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        updateBrokerDeploymentData,
		Verbose:     updateBrokerDeploymentVerbose,
		Silent:      updateBrokerDeploymentSilent,
		IncludeResp: updateBrokerDeploymentIncludeResp,
		UserAgent:   updateBrokerDeploymentUserAgent,
	})
}

func buildUpdateBrokerDeploymentURL(endpoint, version, tenantID, installID, deploymentID string) (string, error) {
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
