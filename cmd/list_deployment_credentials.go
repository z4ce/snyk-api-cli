package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListDeploymentCredentialsCmd represents the list-deployment-credentials command
var ListDeploymentCredentialsCmd = &cobra.Command{
	Use:   "list-deployment-credentials [tenant_id] [install_id] [deployment_id]",
	Short: "List Deployment credentials",
	Long: `List Deployment credentials from the Snyk API.

This command retrieves a list of deployment credentials for a specific tenant, install ID, and deployment ID.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-deployment-credentials 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli list-deployment-credentials 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --limit 10
  snyk-api-cli list-deployment-credentials 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --starting-after abc123
  snyk-api-cli list-deployment-credentials 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runListDeploymentCredentials,
}

var (
	listDeploymentCredentialsStartingAfter string
	listDeploymentCredentialsEndingBefore  string
	listDeploymentCredentialsLimit         int
	listDeploymentCredentialsVerbose       bool
	listDeploymentCredentialsSilent        bool
	listDeploymentCredentialsIncludeResp   bool
	listDeploymentCredentialsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListDeploymentCredentialsCmd.Flags().StringVar(&listDeploymentCredentialsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListDeploymentCredentialsCmd.Flags().StringVar(&listDeploymentCredentialsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListDeploymentCredentialsCmd.Flags().IntVar(&listDeploymentCredentialsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListDeploymentCredentialsCmd.Flags().BoolVarP(&listDeploymentCredentialsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListDeploymentCredentialsCmd.Flags().BoolVarP(&listDeploymentCredentialsSilent, "silent", "s", false, "Silent mode")
	ListDeploymentCredentialsCmd.Flags().BoolVarP(&listDeploymentCredentialsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListDeploymentCredentialsCmd.Flags().StringVarP(&listDeploymentCredentialsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListDeploymentCredentials(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListDeploymentCredentialsURL(endpoint, version, tenantID, installID, deploymentID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listDeploymentCredentialsVerbose,
		Silent:      listDeploymentCredentialsSilent,
		IncludeResp: listDeploymentCredentialsIncludeResp,
		UserAgent:   listDeploymentCredentialsUserAgent,
	})
}

func buildListDeploymentCredentialsURL(endpoint, version, tenantID, installID, deploymentID string, cmd *cobra.Command) (string, error) {
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

	// Add optional parameters if provided
	if listDeploymentCredentialsStartingAfter != "" {
		q.Set("starting_after", listDeploymentCredentialsStartingAfter)
	}
	if listDeploymentCredentialsEndingBefore != "" {
		q.Set("ending_before", listDeploymentCredentialsEndingBefore)
	}
	if listDeploymentCredentialsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listDeploymentCredentialsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
