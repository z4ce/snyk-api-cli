package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListBrokerOrgsForBulkMigrationCmd represents the list-broker-orgs-for-bulk-migration command
var ListBrokerOrgsForBulkMigrationCmd = &cobra.Command{
	Use:   "list-broker-orgs-for-bulk-migration [tenant_id] [install_id] [deployment_id] [connection_id]",
	Short: "List organizations for bulk migration",
	Long: `List organizations for bulk migration from the Snyk API.

This command retrieves a list of organizations available for bulk migration for a specific tenant, install ID, deployment ID, and connection ID.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-broker-orgs-for-bulk-migration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222
  snyk-api-cli list-broker-orgs-for-bulk-migration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --limit 10
  snyk-api-cli list-broker-orgs-for-bulk-migration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --starting-after abc123
  snyk-api-cli list-broker-orgs-for-bulk-migration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runListBrokerOrgsForBulkMigration,
}

var (
	listBrokerOrgsForBulkMigrationStartingAfter string
	listBrokerOrgsForBulkMigrationEndingBefore  string
	listBrokerOrgsForBulkMigrationLimit         int
	listBrokerOrgsForBulkMigrationVerbose       bool
	listBrokerOrgsForBulkMigrationSilent        bool
	listBrokerOrgsForBulkMigrationIncludeResp   bool
	listBrokerOrgsForBulkMigrationUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListBrokerOrgsForBulkMigrationCmd.Flags().StringVar(&listBrokerOrgsForBulkMigrationStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListBrokerOrgsForBulkMigrationCmd.Flags().StringVar(&listBrokerOrgsForBulkMigrationEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListBrokerOrgsForBulkMigrationCmd.Flags().IntVar(&listBrokerOrgsForBulkMigrationLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListBrokerOrgsForBulkMigrationCmd.Flags().BoolVarP(&listBrokerOrgsForBulkMigrationVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListBrokerOrgsForBulkMigrationCmd.Flags().BoolVarP(&listBrokerOrgsForBulkMigrationSilent, "silent", "s", false, "Silent mode")
	ListBrokerOrgsForBulkMigrationCmd.Flags().BoolVarP(&listBrokerOrgsForBulkMigrationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListBrokerOrgsForBulkMigrationCmd.Flags().StringVarP(&listBrokerOrgsForBulkMigrationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListBrokerOrgsForBulkMigration(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	connectionID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListBrokerOrgsForBulkMigrationURL(endpoint, version, tenantID, installID, deploymentID, connectionID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listBrokerOrgsForBulkMigrationVerbose,
		Silent:      listBrokerOrgsForBulkMigrationSilent,
		IncludeResp: listBrokerOrgsForBulkMigrationIncludeResp,
		UserAgent:   listBrokerOrgsForBulkMigrationUserAgent,
	})
}

func buildListBrokerOrgsForBulkMigrationURL(endpoint, version, tenantID, installID, deploymentID, connectionID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/deployments/%s/connections/%s/bulk_migration", endpoint, tenantID, installID, deploymentID, connectionID)

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
	if listBrokerOrgsForBulkMigrationStartingAfter != "" {
		q.Set("starting_after", listBrokerOrgsForBulkMigrationStartingAfter)
	}
	if listBrokerOrgsForBulkMigrationEndingBefore != "" {
		q.Set("ending_before", listBrokerOrgsForBulkMigrationEndingBefore)
	}
	if listBrokerOrgsForBulkMigrationLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listBrokerOrgsForBulkMigrationLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
