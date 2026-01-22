package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateBrokerContextIntegrationCmd represents the update-broker-context-integration command
var UpdateBrokerContextIntegrationCmd = &cobra.Command{
	Use:   "update-broker-context-integration [tenant_id] [install_id] [context_id]",
	Short: "Updates an integration to be associated with a Broker context",
	Long: `Updates an integration to be associated with a Broker context from the Snyk API.

This command updates an integration association for a specific broker context within a tenant and installation.
The request must include the org_id in the attributes, as well as the integration id and type.

Examples:
  snyk-api-cli update-broker-context-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"attributes":{"org_id":"22222222-2222-2222-2222-222222222222"},"id":"integration-uuid","type":"broker_integration"}}'
  snyk-api-cli update-broker-context-integration 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"attributes":{"org_id":"22222222-2222-2222-2222-222222222222"},"id":"integration-uuid","type":"broker_integration"}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runUpdateBrokerContextIntegration,
}

var (
	updateBrokerContextIntegrationData        string
	updateBrokerContextIntegrationVerbose     bool
	updateBrokerContextIntegrationSilent      bool
	updateBrokerContextIntegrationIncludeResp bool
	updateBrokerContextIntegrationUserAgent   string
)

func init() {
	// Add flags for request data
	UpdateBrokerContextIntegrationCmd.Flags().StringVarP(&updateBrokerContextIntegrationData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	UpdateBrokerContextIntegrationCmd.Flags().BoolVarP(&updateBrokerContextIntegrationVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateBrokerContextIntegrationCmd.Flags().BoolVarP(&updateBrokerContextIntegrationSilent, "silent", "s", false, "Silent mode")
	UpdateBrokerContextIntegrationCmd.Flags().BoolVarP(&updateBrokerContextIntegrationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateBrokerContextIntegrationCmd.Flags().StringVarP(&updateBrokerContextIntegrationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	UpdateBrokerContextIntegrationCmd.MarkFlagRequired("data")
}

func runUpdateBrokerContextIntegration(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	contextID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildUpdateBrokerContextIntegrationURL(endpoint, version, tenantID, installID, contextID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        updateBrokerContextIntegrationData,
		Verbose:     updateBrokerContextIntegrationVerbose,
		Silent:      updateBrokerContextIntegrationSilent,
		IncludeResp: updateBrokerContextIntegrationIncludeResp,
		UserAgent:   updateBrokerContextIntegrationUserAgent,
	})
}

func buildUpdateBrokerContextIntegrationURL(endpoint, version, tenantID, installID, contextID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/contexts/%s/integration", endpoint, tenantID, installID, contextID)

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
