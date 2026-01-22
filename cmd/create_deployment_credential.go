package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateDeploymentCredentialCmd represents the create-deployment-credential command
var CreateDeploymentCredentialCmd = &cobra.Command{
	Use:   "create-deployment-credential [tenant_id] [install_id] [deployment_id]",
	Short: "Create deployment credential",
	Long: `Create deployment credential from the Snyk API.

This command creates a new deployment credential for a specific tenant, install ID, and deployment ID.
The request data should be provided in JSON format with deployment_id, environment_variable_name, and type attributes.

Examples:
  snyk-api-cli create-deployment-credential 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"type":"deployment_credential","attributes":[{"deployment_id":"11111111-1111-1111-1111-111111111111","environment_variable_name":"GITHUB_TOKEN","type":"github"}]}}'
  snyk-api-cli create-deployment-credential 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"type":"deployment_credential","attributes":[{"deployment_id":"11111111-1111-1111-1111-111111111111","environment_variable_name":"GITHUB_TOKEN","type":"github","comment":"GitHub access token"}]}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runCreateDeploymentCredential,
}

var (
	createDeploymentCredentialData        string
	createDeploymentCredentialVerbose     bool
	createDeploymentCredentialSilent      bool
	createDeploymentCredentialIncludeResp bool
	createDeploymentCredentialUserAgent   string
)

func init() {
	// Add flags for request data
	CreateDeploymentCredentialCmd.Flags().StringVarP(&createDeploymentCredentialData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	CreateDeploymentCredentialCmd.Flags().BoolVarP(&createDeploymentCredentialVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateDeploymentCredentialCmd.Flags().BoolVarP(&createDeploymentCredentialSilent, "silent", "s", false, "Silent mode")
	CreateDeploymentCredentialCmd.Flags().BoolVarP(&createDeploymentCredentialIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateDeploymentCredentialCmd.Flags().StringVarP(&createDeploymentCredentialUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	CreateDeploymentCredentialCmd.MarkFlagRequired("data")
}

func runCreateDeploymentCredential(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildCreateDeploymentCredentialURL(endpoint, version, tenantID, installID, deploymentID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        createDeploymentCredentialData,
		ContentType: "application/vnd.api+json",
		Verbose:     createDeploymentCredentialVerbose,
		Silent:      createDeploymentCredentialSilent,
		IncludeResp: createDeploymentCredentialIncludeResp,
		UserAgent:   createDeploymentCredentialUserAgent,
	})
}

func buildCreateDeploymentCredentialURL(endpoint, version, tenantID, installID, deploymentID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/credentials", endpoint, tenantID, installID, deploymentID)

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
