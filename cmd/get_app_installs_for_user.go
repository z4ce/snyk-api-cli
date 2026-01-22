package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetAppInstallsForUserCmd represents the get-app-installs-for-user command
var GetAppInstallsForUserCmd = &cobra.Command{
	Use:   "get-app-installs-for-user",
	Short: "Get a list of Snyk Apps installed for a user",
	Long: `Get a list of Snyk Apps installed for a user from the Snyk API.

This command retrieves a list of app installations for the authenticated user,
including details about each installation and optionally expanding app information.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli get-app-installs-for-user
  snyk-api-cli get-app-installs-for-user --expand app
  snyk-api-cli get-app-installs-for-user --limit 10
  snyk-api-cli get-app-installs-for-user --starting-after abc123
  snyk-api-cli get-app-installs-for-user --ending-before xyz789
  snyk-api-cli get-app-installs-for-user --verbose`,
	Args: cobra.NoArgs,
	RunE: runGetAppInstallsForUser,
}

var (
	getAppInstallsForUserExpand        []string
	getAppInstallsForUserLimit         int
	getAppInstallsForUserStartingAfter string
	getAppInstallsForUserEndingBefore  string
	getAppInstallsForUserVerbose       bool
	getAppInstallsForUserSilent        bool
	getAppInstallsForUserIncludeResp   bool
	getAppInstallsForUserUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetAppInstallsForUserCmd.Flags().StringSliceVar(&getAppInstallsForUserExpand, "expand", []string{}, "Comma-separated list of fields to expand (e.g., app)")
	GetAppInstallsForUserCmd.Flags().IntVar(&getAppInstallsForUserLimit, "limit", 0, "Number of results per page")
	GetAppInstallsForUserCmd.Flags().StringVar(&getAppInstallsForUserStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetAppInstallsForUserCmd.Flags().StringVar(&getAppInstallsForUserEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetAppInstallsForUserCmd.Flags().BoolVarP(&getAppInstallsForUserVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAppInstallsForUserCmd.Flags().BoolVarP(&getAppInstallsForUserSilent, "silent", "s", false, "Silent mode")
	GetAppInstallsForUserCmd.Flags().BoolVarP(&getAppInstallsForUserIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAppInstallsForUserCmd.Flags().StringVarP(&getAppInstallsForUserUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAppInstallsForUser(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetAppInstallsForUserURL(endpoint, version, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getAppInstallsForUserVerbose,
		Silent:      getAppInstallsForUserSilent,
		IncludeResp: getAppInstallsForUserIncludeResp,
		UserAgent:   getAppInstallsForUserUserAgent,
	})
}

func buildGetAppInstallsForUserURL(endpoint, version string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/self/apps/installs", endpoint)

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
	if len(getAppInstallsForUserExpand) > 0 {
		// Handle expand as an array parameter
		for _, expand := range getAppInstallsForUserExpand {
			q.Add("expand", expand)
		}
	}
	if getAppInstallsForUserLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getAppInstallsForUserLimit))
	}
	if getAppInstallsForUserStartingAfter != "" {
		q.Set("starting_after", getAppInstallsForUserStartingAfter)
	}
	if getAppInstallsForUserEndingBefore != "" {
		q.Set("ending_before", getAppInstallsForUserEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
