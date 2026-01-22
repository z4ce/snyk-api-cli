package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteDeploymentCredentialCmd represents the delete-deployment-credential command
var DeleteDeploymentCredentialCmd = &cobra.Command{
	Use:   "delete-deployment-credential [tenant_id] [install_id] [deployment_id] [credential_id]",
	Short: "Deletes Deployment credential",
	Long: `Deletes Deployment credential from the Snyk API.

This command deletes an existing deployment credential for a specific tenant, install ID, deployment ID, and credential ID.

Examples:
  snyk-api-cli delete-deployment-credential 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222
  snyk-api-cli delete-deployment-credential 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runDeleteDeploymentCredential,
}

var (
	deleteDeploymentCredentialVerbose     bool
	deleteDeploymentCredentialSilent      bool
	deleteDeploymentCredentialIncludeResp bool
	deleteDeploymentCredentialUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteDeploymentCredentialCmd.Flags().BoolVarP(&deleteDeploymentCredentialVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteDeploymentCredentialCmd.Flags().BoolVarP(&deleteDeploymentCredentialSilent, "silent", "s", false, "Silent mode")
	DeleteDeploymentCredentialCmd.Flags().BoolVarP(&deleteDeploymentCredentialIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteDeploymentCredentialCmd.Flags().StringVarP(&deleteDeploymentCredentialUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteDeploymentCredential(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	credentialID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildDeleteDeploymentCredentialURL(endpoint, version, tenantID, installID, deploymentID, credentialID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteDeploymentCredentialVerbose,
		Silent:      deleteDeploymentCredentialSilent,
		IncludeResp: deleteDeploymentCredentialIncludeResp,
		UserAgent:   deleteDeploymentCredentialUserAgent,
	})
}

func buildDeleteDeploymentCredentialURL(endpoint, version, tenantID, installID, deploymentID, credentialID string) (string, error) {
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
