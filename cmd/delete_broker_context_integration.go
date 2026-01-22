package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteBrokerContextIntegrationCmd represents the delete-broker-context-integration command
var DeleteBrokerContextIntegrationCmd = &cobra.Command{
	Use:   "delete-broker-context-integration [tenant_id] [install_id] [context_id] [integration_id]",
	Short: "Deletes the Broker context association with an Integration",
	Long: `Deletes the Broker context association with an Integration from the Snyk API.

This command deletes the association between a broker context and an integration within a tenant and installation.
The integration association will be permanently removed from the broker context.

Examples:
  snyk-api-cli delete-broker-context-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222
  snyk-api-cli delete-broker-context-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 22222222-2222-2222-2222-222222222222 --verbose`,
	Args: cobra.ExactArgs(4),
	RunE: runDeleteBrokerContextIntegration,
}

var (
	deleteBrokerContextIntegrationVerbose     bool
	deleteBrokerContextIntegrationSilent      bool
	deleteBrokerContextIntegrationIncludeResp bool
	deleteBrokerContextIntegrationUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteBrokerContextIntegrationCmd.Flags().BoolVarP(&deleteBrokerContextIntegrationVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteBrokerContextIntegrationCmd.Flags().BoolVarP(&deleteBrokerContextIntegrationSilent, "silent", "s", false, "Silent mode")
	DeleteBrokerContextIntegrationCmd.Flags().BoolVarP(&deleteBrokerContextIntegrationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteBrokerContextIntegrationCmd.Flags().StringVarP(&deleteBrokerContextIntegrationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteBrokerContextIntegration(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	contextID := args[2]
	integrationID := args[3]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildDeleteBrokerContextIntegrationURL(endpoint, version, tenantID, installID, contextID, integrationID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteBrokerContextIntegrationVerbose,
		Silent:      deleteBrokerContextIntegrationSilent,
		IncludeResp: deleteBrokerContextIntegrationIncludeResp,
		UserAgent:   deleteBrokerContextIntegrationUserAgent,
	})
}

func buildDeleteBrokerContextIntegrationURL(endpoint, version, tenantID, installID, contextID, integrationID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/contexts/%s/integrations/%s", endpoint, tenantID, installID, contextID, integrationID)

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
