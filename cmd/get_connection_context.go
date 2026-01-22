package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetConnectionContextCmd represents the get-connection-context command
var GetConnectionContextCmd = &cobra.Command{
	Use:   "get-connection-context [tenant_id] [install_id] [context_id]",
	Short: "List Connection context",
	Long: `List Connection context from the Snyk API.

This command retrieves a specific broker context by context ID within a tenant and installation.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli get-connection-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli get-connection-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --limit 10
  snyk-api-cli get-connection-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --starting-after abc123
  snyk-api-cli get-connection-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --ending-before xyz789
  snyk-api-cli get-connection-context 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runGetConnectionContext,
}

var (
	getConnectionContextStartingAfter string
	getConnectionContextEndingBefore  string
	getConnectionContextLimit         int
	getConnectionContextVerbose       bool
	getConnectionContextSilent        bool
	getConnectionContextIncludeResp   bool
	getConnectionContextUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetConnectionContextCmd.Flags().StringVar(&getConnectionContextStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetConnectionContextCmd.Flags().StringVar(&getConnectionContextEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	GetConnectionContextCmd.Flags().IntVar(&getConnectionContextLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	GetConnectionContextCmd.Flags().BoolVarP(&getConnectionContextVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetConnectionContextCmd.Flags().BoolVarP(&getConnectionContextSilent, "silent", "s", false, "Silent mode")
	GetConnectionContextCmd.Flags().BoolVarP(&getConnectionContextIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetConnectionContextCmd.Flags().StringVarP(&getConnectionContextUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetConnectionContext(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	contextID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetConnectionContextURL(endpoint, version, tenantID, installID, contextID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getConnectionContextVerbose,
		Silent:      getConnectionContextSilent,
		IncludeResp: getConnectionContextIncludeResp,
		UserAgent:   getConnectionContextUserAgent,
	})
}

func buildGetConnectionContextURL(endpoint, version, tenantID, installID, contextID string, cmd *cobra.Command) (string, error) {
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

	// Add optional parameters if provided
	if getConnectionContextStartingAfter != "" {
		q.Set("starting_after", getConnectionContextStartingAfter)
	}
	if getConnectionContextEndingBefore != "" {
		q.Set("ending_before", getConnectionContextEndingBefore)
	}
	if getConnectionContextLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getConnectionContextLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
