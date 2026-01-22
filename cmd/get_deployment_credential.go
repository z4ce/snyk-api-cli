package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetDeploymentCredentialCmd represents the get-deployment-credential command
var GetDeploymentCredentialCmd = &cobra.Command{
	Use:   "get-deployment-credential [tenant_id] [install_id] [deployment_id] [credential_id]",
	Short: "Get Deployment credential",
	Long: `Get Deployment credential from the Snyk API.

This command retrieves details of a specific deployment credential for a tenant, install ID, deployment ID, and credential ID.

Examples:
  snyk-api-cli get-deployment-credential 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222
  snyk-api-cli get-deployment-credential 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runGetDeploymentCredential,
}

var (
	getDeploymentCredentialVerbose     bool
	getDeploymentCredentialSilent      bool
	getDeploymentCredentialIncludeResp bool
	getDeploymentCredentialUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetDeploymentCredentialCmd.Flags().BoolVarP(&getDeploymentCredentialVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetDeploymentCredentialCmd.Flags().BoolVarP(&getDeploymentCredentialSilent, "silent", "s", false, "Silent mode")
	GetDeploymentCredentialCmd.Flags().BoolVarP(&getDeploymentCredentialIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetDeploymentCredentialCmd.Flags().StringVarP(&getDeploymentCredentialUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetDeploymentCredential(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	credentialID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetDeploymentCredentialURL(endpoint, version, tenantID, installID, deploymentID, credentialID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getDeploymentCredentialVerbose,
		Silent:      getDeploymentCredentialSilent,
		IncludeResp: getDeploymentCredentialIncludeResp,
		UserAgent:   getDeploymentCredentialUserAgent,
	})
}

func buildGetDeploymentCredentialURL(endpoint, version, tenantID, installID, deploymentID, credentialID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/credentials/%s", endpoint, tenantID, installID, deploymentID, credentialID)

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
