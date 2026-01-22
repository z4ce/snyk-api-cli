package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateBrokerDeploymentCmd represents the create-broker-deployment command
var CreateBrokerDeploymentCmd = &cobra.Command{
	Use:   "create-broker-deployment [tenant_id] [install_id]",
	Short: "Creates Broker Deployment",
	Long: `Creates Broker Deployment from the Snyk API.

This command creates a new broker deployment for a specific tenant and install ID.
The request data should be provided in JSON format.

Examples:
  snyk-api-cli create-broker-deployment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --data '{"data":{"type":"broker_deployment","attributes":{}}}'
  snyk-api-cli create-broker-deployment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --data '{"data":{"type":"broker_deployment","attributes":{}}}' --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runCreateBrokerDeployment,
}

var (
	createBrokerDeploymentData        string
	createBrokerDeploymentVerbose     bool
	createBrokerDeploymentSilent      bool
	createBrokerDeploymentIncludeResp bool
	createBrokerDeploymentUserAgent   string
)

func init() {
	// Add flags for request data
	CreateBrokerDeploymentCmd.Flags().StringVarP(&createBrokerDeploymentData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	CreateBrokerDeploymentCmd.Flags().BoolVarP(&createBrokerDeploymentVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateBrokerDeploymentCmd.Flags().BoolVarP(&createBrokerDeploymentSilent, "silent", "s", false, "Silent mode")
	CreateBrokerDeploymentCmd.Flags().BoolVarP(&createBrokerDeploymentIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateBrokerDeploymentCmd.Flags().StringVarP(&createBrokerDeploymentUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	CreateBrokerDeploymentCmd.MarkFlagRequired("data")
}

func runCreateBrokerDeployment(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildCreateBrokerDeploymentURL(endpoint, version, tenantID, installID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        createBrokerDeploymentData,
		ContentType: "application/vnd.api+json",
		Verbose:     createBrokerDeploymentVerbose,
		Silent:      createBrokerDeploymentSilent,
		IncludeResp: createBrokerDeploymentIncludeResp,
		UserAgent:   createBrokerDeploymentUserAgent,
	})
}

func buildCreateBrokerDeploymentURL(endpoint, version, tenantID, installID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments", endpoint, tenantID, installID)

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
