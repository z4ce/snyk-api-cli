package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetAppsCmd represents the get-apps command
var GetAppsCmd = &cobra.Command{
	Use:   "get-apps [org_id]",
	Short: "Get organization apps from Snyk",
	Long: `Get organization apps from the Snyk API.

This command retrieves a list of apps for the specified organization.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli get-apps 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-apps 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli get-apps 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli get-apps 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli get-apps 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runGetApps,
}

var (
	getAppsStartingAfter string
	getAppsEndingBefore  string
	getAppsLimit         int
	getAppsVerbose       bool
	getAppsSilent        bool
	getAppsIncludeResp   bool
	getAppsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetAppsCmd.Flags().StringVar(&getAppsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetAppsCmd.Flags().StringVar(&getAppsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	GetAppsCmd.Flags().IntVar(&getAppsLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	GetAppsCmd.Flags().BoolVarP(&getAppsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAppsCmd.Flags().BoolVarP(&getAppsSilent, "silent", "s", false, "Silent mode")
	GetAppsCmd.Flags().BoolVarP(&getAppsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAppsCmd.Flags().StringVarP(&getAppsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetApps(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetAppsURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getAppsVerbose,
		Silent:      getAppsSilent,
		IncludeResp: getAppsIncludeResp,
		UserAgent:   getAppsUserAgent,
	})
}

func buildGetAppsURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps", endpoint, orgID)

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
	if getAppsStartingAfter != "" {
		q.Set("starting_after", getAppsStartingAfter)
	}
	if getAppsEndingBefore != "" {
		q.Set("ending_before", getAppsEndingBefore)
	}
	if getAppsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getAppsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
