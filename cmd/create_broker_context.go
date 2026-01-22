package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateBrokerContextCmd represents the create-broker-context command
var CreateBrokerContextCmd = &cobra.Command{
	Use:   "create-broker-context [tenant_id] [install_id] [deployment_id]",
	Short: "Create broker Context",
	Long: `Create broker Context from the Snyk API.

This command creates a new broker context for a specific tenant, install ID, and deployment ID.
The request data should be provided in JSON format with connection_id and context attributes.

Examples:
  snyk-api-cli create-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"type":"broker_context","attributes":{"connection_id":"22222222-2222-2222-2222-222222222222","context":{}}}}'
  snyk-api-cli create-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"type":"broker_context","attributes":{"connection_id":"22222222-2222-2222-2222-222222222222","context":{}}}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runCreateBrokerContext,
}

var (
	createBrokerContextData        string
	createBrokerContextVerbose     bool
	createBrokerContextSilent      bool
	createBrokerContextIncludeResp bool
	createBrokerContextUserAgent   string
)

func init() {
	// Add flags for request data
	CreateBrokerContextCmd.Flags().StringVarP(&createBrokerContextData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	CreateBrokerContextCmd.Flags().BoolVarP(&createBrokerContextVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateBrokerContextCmd.Flags().BoolVarP(&createBrokerContextSilent, "silent", "s", false, "Silent mode")
	CreateBrokerContextCmd.Flags().BoolVarP(&createBrokerContextIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateBrokerContextCmd.Flags().StringVarP(&createBrokerContextUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	CreateBrokerContextCmd.MarkFlagRequired("data")
}

func runCreateBrokerContext(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	deploymentID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildCreateBrokerContextURL(endpoint, version, tenantID, installID, deploymentID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        createBrokerContextData,
		ContentType: "application/vnd.api+json",
		Verbose:     createBrokerContextVerbose,
		Silent:      createBrokerContextSilent,
		IncludeResp: createBrokerContextIncludeResp,
		UserAgent:   createBrokerContextUserAgent,
	})
}

func buildCreateBrokerContextURL(endpoint, version, tenantID, installID, deploymentID string) (string, error) {
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

	u.RawQuery = q.Encode()
	return u.String(), nil
}
