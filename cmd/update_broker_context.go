package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateBrokerContextCmd represents the update-broker-context command
var UpdateBrokerContextCmd = &cobra.Command{
	Use:   "update-broker-context [tenant_id] [install_id] [context_id]",
	Short: "Updates Broker Context",
	Long: `Updates Broker Context from the Snyk API.

This command updates a broker context configuration for a specific tenant and installation.
The request must include the context data, id, and type in the JSON payload.

Examples:
  snyk-api-cli update-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"attributes":{"context":{}},"id":"11111111-1111-1111-1111-111111111111","type":"broker_context"}}'
  snyk-api-cli update-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --data '{"data":{"attributes":{"context":{"key":"value"}},"id":"11111111-1111-1111-1111-111111111111","type":"broker_context"}}' --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runUpdateBrokerContext,
}

var (
	updateBrokerContextData        string
	updateBrokerContextVerbose     bool
	updateBrokerContextSilent      bool
	updateBrokerContextIncludeResp bool
	updateBrokerContextUserAgent   string
)

func init() {
	// Add flags for request data
	UpdateBrokerContextCmd.Flags().StringVarP(&updateBrokerContextData, "data", "d", "", "JSON data to send in request body")

	// Add standard flags like other commands
	UpdateBrokerContextCmd.Flags().BoolVarP(&updateBrokerContextVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateBrokerContextCmd.Flags().BoolVarP(&updateBrokerContextSilent, "silent", "s", false, "Silent mode")
	UpdateBrokerContextCmd.Flags().BoolVarP(&updateBrokerContextIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateBrokerContextCmd.Flags().StringVarP(&updateBrokerContextUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark data flag as required
	UpdateBrokerContextCmd.MarkFlagRequired("data")
}

func runUpdateBrokerContext(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	contextID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildUpdateBrokerContextURL(endpoint, version, tenantID, installID, contextID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        updateBrokerContextData,
		Verbose:     updateBrokerContextVerbose,
		Silent:      updateBrokerContextSilent,
		IncludeResp: updateBrokerContextIncludeResp,
		UserAgent:   updateBrokerContextUserAgent,
	})
}

func buildUpdateBrokerContextURL(endpoint, version, tenantID, installID, contextID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/contexts/%s", endpoint, tenantID, installID, contextID)

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
