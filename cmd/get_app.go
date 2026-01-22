package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetAppCmd represents the get-app command
var GetAppCmd = &cobra.Command{
	Use:   "get-app [org_id] [client_id]",
	Short: "Get details of a specific app by client ID from an organization",
	Long: `Get details of a specific app by client ID from an organization in the Snyk API.

This command retrieves detailed information about a specific app within an organization
by providing both the organization ID and client ID as required arguments.

The organization ID and client ID must be provided as UUIDs.

Note: This endpoint is deprecated. Consider using get-app-by-id instead.

Examples:
  snyk-api-cli get-app 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-app 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-app 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetApp,
}

var (
	getAppVerbose     bool
	getAppSilent      bool
	getAppIncludeResp bool
	getAppUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetAppCmd.Flags().BoolVarP(&getAppVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAppCmd.Flags().BoolVarP(&getAppSilent, "silent", "s", false, "Silent mode")
	GetAppCmd.Flags().BoolVarP(&getAppIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAppCmd.Flags().StringVarP(&getAppUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetApp(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	clientID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetAppURL(endpoint, version, orgID, clientID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getAppVerbose,
		Silent:      getAppSilent,
		IncludeResp: getAppIncludeResp,
		UserAgent:   getAppUserAgent,
	})
}

func buildGetAppURL(endpoint, version, orgID, clientID string) (string, error) {
	// Build base URL with org ID and client ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/%s", endpoint, orgID, clientID)

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
