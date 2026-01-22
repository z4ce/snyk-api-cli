package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateBrokerOrgsForBulkMigrationCmd represents the create-broker-orgs-for-bulk-migration command
var CreateBrokerOrgsForBulkMigrationCmd = &cobra.Command{
	Use:   "create-broker-orgs-for-bulk-migration [tenant_id] [install_id] [deployment_id] [connection_id]",
	Short: "Performs bulk migration integrations to universal broker",
	Long: `Performs bulk migration integrations to universal broker from the Snyk API.

This command performs bulk migration integrations from legacy to universal broker for a specific tenant, install ID, deployment ID, and connection ID.
The request data should be provided in JSON format.

Examples:
  snyk-api-cli create-broker-orgs-for-bulk-migration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --data '{"data":{"type":"broker_migration"}}'
  snyk-api-cli create-broker-orgs-for-bulk-migration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --data '{"data":{"type":"broker_migration"}}' --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runCreateBrokerOrgsForBulkMigration,
}

var (
	createBrokerOrgsForBulkMigrationData        string
	createBrokerOrgsForBulkMigrationVerbose     bool
	createBrokerOrgsForBulkMigrationSilent      bool
	createBrokerOrgsForBulkMigrationIncludeResp bool
	createBrokerOrgsForBulkMigrationUserAgent   string
)

func init() {
	// Add flags for request data
	CreateBrokerOrgsForBulkMigrationCmd.Flags().StringVarP(&createBrokerOrgsForBulkMigrationData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	CreateBrokerOrgsForBulkMigrationCmd.Flags().BoolVarP(&createBrokerOrgsForBulkMigrationVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateBrokerOrgsForBulkMigrationCmd.Flags().BoolVarP(&createBrokerOrgsForBulkMigrationSilent, "silent", "s", false, "Silent mode")
	CreateBrokerOrgsForBulkMigrationCmd.Flags().BoolVarP(&createBrokerOrgsForBulkMigrationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateBrokerOrgsForBulkMigrationCmd.Flags().StringVarP(&createBrokerOrgsForBulkMigrationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	CreateBrokerOrgsForBulkMigrationCmd.MarkFlagRequired("data")
}

func runCreateBrokerOrgsForBulkMigration(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	connectionID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildCreateBrokerOrgsForBulkMigrationURL(endpoint, version, tenantID, installID, deploymentID, connectionID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        createBrokerOrgsForBulkMigrationData,
		ContentType: "application/vnd.api+json",
		Verbose:     createBrokerOrgsForBulkMigrationVerbose,
		Silent:      createBrokerOrgsForBulkMigrationSilent,
		IncludeResp: createBrokerOrgsForBulkMigrationIncludeResp,
		UserAgent:   createBrokerOrgsForBulkMigrationUserAgent,
	})
}

func buildCreateBrokerOrgsForBulkMigrationURL(endpoint, version, tenantID, installID, deploymentID, connectionID string) (string, error) {
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

	u.RawQuery = q.Encode()
	return u.String(), nil
}
