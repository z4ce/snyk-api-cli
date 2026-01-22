package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetUserInstalledAppsCmd represents the get-user-installed-apps command
var GetUserInstalledAppsCmd = &cobra.Command{
	Use:   "get-user-installed-apps",
	Short: "Get a list of Snyk Apps that can act on your behalf",
	Long: `Get a list of Snyk Apps that can act on your behalf from the Snyk API.

This command retrieves a list of Snyk Apps that the authenticated user has installed
and that can act on the user's behalf. The results can be paginated using various
query parameters.

Examples:
  snyk-api-cli get-user-installed-apps
  snyk-api-cli get-user-installed-apps --limit 10
  snyk-api-cli get-user-installed-apps --starting-after abc123
  snyk-api-cli get-user-installed-apps --ending-before xyz789
  snyk-api-cli get-user-installed-apps --verbose`,
	Args: cobra.NoArgs,
	RunE: runGetUserInstalledApps,
}

var (
	getUserInstalledAppsLimit         int
	getUserInstalledAppsStartingAfter string
	getUserInstalledAppsEndingBefore  string
	getUserInstalledAppsVerbose       bool
	getUserInstalledAppsSilent        bool
	getUserInstalledAppsIncludeResp   bool
	getUserInstalledAppsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetUserInstalledAppsCmd.Flags().IntVar(&getUserInstalledAppsLimit, "limit", 0, "Number of results per page")
	GetUserInstalledAppsCmd.Flags().StringVar(&getUserInstalledAppsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetUserInstalledAppsCmd.Flags().StringVar(&getUserInstalledAppsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetUserInstalledAppsCmd.Flags().BoolVarP(&getUserInstalledAppsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetUserInstalledAppsCmd.Flags().BoolVarP(&getUserInstalledAppsSilent, "silent", "s", false, "Silent mode")
	GetUserInstalledAppsCmd.Flags().BoolVarP(&getUserInstalledAppsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetUserInstalledAppsCmd.Flags().StringVarP(&getUserInstalledAppsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetUserInstalledApps(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetUserInstalledAppsURL(endpoint, version, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getUserInstalledAppsVerbose,
		Silent:      getUserInstalledAppsSilent,
		IncludeResp: getUserInstalledAppsIncludeResp,
		UserAgent:   getUserInstalledAppsUserAgent,
	})
}

func buildGetUserInstalledAppsURL(endpoint, version string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/self/apps", endpoint)

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
	if getUserInstalledAppsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getUserInstalledAppsLimit))
	}
	if getUserInstalledAppsStartingAfter != "" {
		q.Set("starting_after", getUserInstalledAppsStartingAfter)
	}
	if getUserInstalledAppsEndingBefore != "" {
		q.Set("ending_before", getUserInstalledAppsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
