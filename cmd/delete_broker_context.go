package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteBrokerContextCmd represents the delete-broker-context command
var DeleteBrokerContextCmd = &cobra.Command{
	Use:   "delete-broker-context [tenant_id] [install_id] [context_id]",
	Short: "Deletes broker context",
	Long: `Deletes broker context from the Snyk API.

This command deletes a broker context configuration for a specific tenant and installation.
The broker context will be permanently removed.

Examples:
  snyk-api-cli delete-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli delete-broker-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runDeleteBrokerContext,
}

var (
	deleteBrokerContextVerbose     bool
	deleteBrokerContextSilent      bool
	deleteBrokerContextIncludeResp bool
	deleteBrokerContextUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteBrokerContextCmd.Flags().BoolVarP(&deleteBrokerContextVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteBrokerContextCmd.Flags().BoolVarP(&deleteBrokerContextSilent, "silent", "s", false, "Silent mode")
	DeleteBrokerContextCmd.Flags().BoolVarP(&deleteBrokerContextIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteBrokerContextCmd.Flags().StringVarP(&deleteBrokerContextUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteBrokerContext(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	contextID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildDeleteBrokerContextURL(endpoint, version, tenantID, installID, contextID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteBrokerContextVerbose,
		Silent:      deleteBrokerContextSilent,
		IncludeResp: deleteBrokerContextIncludeResp,
		UserAgent:   deleteBrokerContextUserAgent,
	})
}

func buildDeleteBrokerContextURL(endpoint, version, tenantID, installID, contextID string) (string, error) {
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
