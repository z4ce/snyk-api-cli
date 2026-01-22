package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListConnectionContextsCmd represents the list-connection-contexts command
var ListConnectionContextsCmd = &cobra.Command{
	Use:   "list-connection-contexts [tenant_id] [install_id] [connection_id]",
	Short: "List Connection contexts",
	Long: `List Connection contexts from the Snyk API.

This command retrieves a list of broker contexts for a specific connection within a tenant and installation.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-connection-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111
  snyk-api-cli list-connection-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --limit 10
  snyk-api-cli list-connection-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --starting-after abc123
  snyk-api-cli list-connection-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --ending-before xyz789
  snyk-api-cli list-connection-contexts 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11111111-1111-1111-1111-111111111111 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runListConnectionContexts,
}

var (
	listConnectionContextsStartingAfter string
	listConnectionContextsEndingBefore  string
	listConnectionContextsLimit         int
	listConnectionContextsVerbose       bool
	listConnectionContextsSilent        bool
	listConnectionContextsIncludeResp   bool
	listConnectionContextsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListConnectionContextsCmd.Flags().StringVar(&listConnectionContextsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListConnectionContextsCmd.Flags().StringVar(&listConnectionContextsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListConnectionContextsCmd.Flags().IntVar(&listConnectionContextsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	ListConnectionContextsCmd.Flags().BoolVarP(&listConnectionContextsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListConnectionContextsCmd.Flags().BoolVarP(&listConnectionContextsSilent, "silent", "s", false, "Silent mode")
	ListConnectionContextsCmd.Flags().BoolVarP(&listConnectionContextsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListConnectionContextsCmd.Flags().StringVarP(&listConnectionContextsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListConnectionContexts(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	installID := args[1]
	connectionID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListConnectionContextsURL(endpoint, version, tenantID, installID, connectionID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listConnectionContextsVerbose,
		Silent:      listConnectionContextsSilent,
		IncludeResp: listConnectionContextsIncludeResp,
		UserAgent:   listConnectionContextsUserAgent,
	})
}

func buildListConnectionContextsURL(endpoint, version, tenantID, installID, connectionID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/brokers/installs/%s/connections/%s/contexts", endpoint, tenantID, installID, connectionID)

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
	if listConnectionContextsStartingAfter != "" {
		q.Set("starting_after", listConnectionContextsStartingAfter)
	}
	if listConnectionContextsEndingBefore != "" {
		q.Set("ending_before", listConnectionContextsEndingBefore)
	}
	if listConnectionContextsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listConnectionContextsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
