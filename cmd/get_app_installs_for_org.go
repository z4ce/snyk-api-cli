package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetAppInstallsForOrgCmd represents the get-app-installs-for-org command
var GetAppInstallsForOrgCmd = &cobra.Command{
	Use:   "get-app-installs-for-org [org_id]",
	Short: "Get app installations for a specific organization from Snyk",
	Long: `Get app installations for a specific organization from the Snyk API.

This command retrieves app installations that are associated with a specific organization by its ID.
The organization ID must be provided as a required argument.

Examples:
  snyk-api-cli get-app-installs-for-org 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-app-installs-for-org 12345678-1234-1234-1234-123456789012 --expand app --limit 10
  snyk-api-cli get-app-installs-for-org 12345678-1234-1234-1234-123456789012 --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetAppInstallsForOrg,
}

var (
	getAppInstallsForOrgExpand        []string
	getAppInstallsForOrgStartingAfter string
	getAppInstallsForOrgEndingBefore  string
	getAppInstallsForOrgLimit         int
	getAppInstallsForOrgVerbose       bool
	getAppInstallsForOrgSilent        bool
	getAppInstallsForOrgIncludeResp   bool
	getAppInstallsForOrgUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetAppInstallsForOrgCmd.Flags().StringSliceVar(&getAppInstallsForOrgExpand, "expand", []string{}, "Expand relationships (allowed values: app)")
	GetAppInstallsForOrgCmd.Flags().StringVar(&getAppInstallsForOrgStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetAppInstallsForOrgCmd.Flags().StringVar(&getAppInstallsForOrgEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	GetAppInstallsForOrgCmd.Flags().IntVar(&getAppInstallsForOrgLimit, "limit", 0, "Number of results to return per page")

	// Add standard flags like other commands
	GetAppInstallsForOrgCmd.Flags().BoolVarP(&getAppInstallsForOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAppInstallsForOrgCmd.Flags().BoolVarP(&getAppInstallsForOrgSilent, "silent", "s", false, "Silent mode")
	GetAppInstallsForOrgCmd.Flags().BoolVarP(&getAppInstallsForOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAppInstallsForOrgCmd.Flags().StringVarP(&getAppInstallsForOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAppInstallsForOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetAppInstallsForOrgURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getAppInstallsForOrgVerbose,
		Silent:      getAppInstallsForOrgSilent,
		IncludeResp: getAppInstallsForOrgIncludeResp,
		UserAgent:   getAppInstallsForOrgUserAgent,
	})
}

func buildGetAppInstallsForOrgURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/installs", endpoint, orgID)

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
	if len(getAppInstallsForOrgExpand) > 0 {
		// Handle expand as an array parameter
		for _, expand := range getAppInstallsForOrgExpand {
			q.Add("expand", expand)
		}
	}
	if getAppInstallsForOrgStartingAfter != "" {
		q.Set("starting_after", getAppInstallsForOrgStartingAfter)
	}
	if getAppInstallsForOrgEndingBefore != "" {
		q.Set("ending_before", getAppInstallsForOrgEndingBefore)
	}
	if getAppInstallsForOrgLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getAppInstallsForOrgLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
