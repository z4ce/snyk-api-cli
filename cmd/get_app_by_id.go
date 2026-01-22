package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetAppByIDCmd represents the get-app-by-id command
var GetAppByIDCmd = &cobra.Command{
	Use:   "get-app-by-id [org_id] [app_id]",
	Short: "Get details of a specific app by ID from an organization",
	Long: `Get details of a specific app by ID from an organization in the Snyk API.

This command retrieves detailed information about a specific app within an organization
by providing both the organization ID and app ID as required arguments.

The organization ID and app ID must be provided as UUIDs.

Examples:
  snyk-api-cli get-app-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-app-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-app-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetAppByID,
}

var (
	getAppByIDVerbose     bool
	getAppByIDSilent      bool
	getAppByIDIncludeResp bool
	getAppByIDUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetAppByIDCmd.Flags().BoolVarP(&getAppByIDVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAppByIDCmd.Flags().BoolVarP(&getAppByIDSilent, "silent", "s", false, "Silent mode")
	GetAppByIDCmd.Flags().BoolVarP(&getAppByIDIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAppByIDCmd.Flags().StringVarP(&getAppByIDUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAppByID(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	appID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetAppByIDURL(endpoint, version, orgID, appID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getAppByIDVerbose,
		Silent:      getAppByIDSilent,
		IncludeResp: getAppByIDIncludeResp,
		UserAgent:   getAppByIDUserAgent,
	})
}

func buildGetAppByIDURL(endpoint, version, orgID, appID string) (string, error) {
	// Build base URL with org ID and app ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/creations/%s", endpoint, orgID, appID)

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
