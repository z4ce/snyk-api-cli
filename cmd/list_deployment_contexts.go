package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListDeploymentContextsCmd represents the list-deployment-contexts command
var ListDeploymentContextsCmd = &cobra.Command{
	Use:   "list-deployment-contexts [tenant_id] [install_id] [deployment_id]",
	Short: "List Deployment contexts",
	Long: `List Deployment contexts from the Snyk API.

This command retrieves a list of deployment contexts for a specific tenant, install ID, and deployment ID.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-deployment-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli list-deployment-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --limit 10
  snyk-api-cli list-deployment-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --starting-after abc123
  snyk-api-cli list-deployment-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runListDeploymentContexts,
}

var (
	listDeploymentContextsStartingAfter string
	listDeploymentContextsEndingBefore  string
	listDeploymentContextsLimit         int
	listDeploymentContextsVerbose       bool
	listDeploymentContextsSilent        bool
	listDeploymentContextsIncludeResp   bool
	listDeploymentContextsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListDeploymentContextsCmd.Flags().StringVar(&listDeploymentContextsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListDeploymentContextsCmd.Flags().StringVar(&listDeploymentContextsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListDeploymentContextsCmd.Flags().IntVar(&listDeploymentContextsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListDeploymentContextsCmd.Flags().BoolVarP(&listDeploymentContextsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListDeploymentContextsCmd.Flags().BoolVarP(&listDeploymentContextsSilent, "silent", "s", false, "Silent mode")
	ListDeploymentContextsCmd.Flags().BoolVarP(&listDeploymentContextsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListDeploymentContextsCmd.Flags().StringVarP(&listDeploymentContextsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListDeploymentContexts(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListDeploymentContextsURL(endpoint, version, tenantID, installID, deploymentID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listDeploymentContextsVerbose,
		Silent:      listDeploymentContextsSilent,
		IncludeResp: listDeploymentContextsIncludeResp,
		UserAgent:   listDeploymentContextsUserAgent,
	})
}

func buildListDeploymentContextsURL(endpoint, version, tenantID, installID, deploymentID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/contexts", endpoint, tenantID, installID, deploymentID)

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
	if listDeploymentContextsStartingAfter != "" {
		q.Set("starting_after", listDeploymentContextsStartingAfter)
	}
	if listDeploymentContextsEndingBefore != "" {
		q.Set("ending_before", listDeploymentContextsEndingBefore)
	}
	if listDeploymentContextsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listDeploymentContextsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
