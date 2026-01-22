package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetAccessRequestsCmd represents the get-access-requests command
var GetAccessRequestsCmd = &cobra.Command{
	Use:   "get-access-requests",
	Short: "Get access requests from Snyk",
	Long: `Get access requests from the Snyk API.

This command retrieves a list of access requests for the authenticated user.
The results can be filtered and paginated using various query parameters.

Examples:
  snyk-api-cli get-access-requests
  snyk-api-cli get-access-requests --limit 10
  snyk-api-cli get-access-requests --org-ids org1,org2
  snyk-api-cli get-access-requests --starting-after abc123
  snyk-api-cli get-access-requests --ending-before xyz789
  snyk-api-cli get-access-requests --verbose`,
	Args: cobra.NoArgs,
	RunE: runGetAccessRequests,
}

var (
	getAccessRequestsOrgIDs        []string
	getAccessRequestsLimit         int
	getAccessRequestsStartingAfter string
	getAccessRequestsEndingBefore  string
	getAccessRequestsVerbose       bool
	getAccessRequestsSilent        bool
	getAccessRequestsIncludeResp   bool
	getAccessRequestsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetAccessRequestsCmd.Flags().StringSliceVar(&getAccessRequestsOrgIDs, "org-ids", []string{}, "Organization ID filter (can be used multiple times)")
	GetAccessRequestsCmd.Flags().IntVar(&getAccessRequestsLimit, "limit", 0, "Number of results per page")
	GetAccessRequestsCmd.Flags().StringVar(&getAccessRequestsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetAccessRequestsCmd.Flags().StringVar(&getAccessRequestsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetAccessRequestsCmd.Flags().BoolVarP(&getAccessRequestsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAccessRequestsCmd.Flags().BoolVarP(&getAccessRequestsSilent, "silent", "s", false, "Silent mode")
	GetAccessRequestsCmd.Flags().BoolVarP(&getAccessRequestsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAccessRequestsCmd.Flags().StringVarP(&getAccessRequestsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAccessRequests(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetAccessRequestsURL(endpoint, version, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getAccessRequestsVerbose,
		Silent:      getAccessRequestsSilent,
		IncludeResp: getAccessRequestsIncludeResp,
		UserAgent:   getAccessRequestsUserAgent,
	})
}

func buildGetAccessRequestsURL(endpoint, version string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/self/access_requests", endpoint)

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
	if len(getAccessRequestsOrgIDs) > 0 {
		// Handle org_id as an array parameter
		for _, orgID := range getAccessRequestsOrgIDs {
			q.Add("org_id", orgID)
		}
	}
	if getAccessRequestsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getAccessRequestsLimit))
	}
	if getAccessRequestsStartingAfter != "" {
		q.Set("starting_after", getAccessRequestsStartingAfter)
	}
	if getAccessRequestsEndingBefore != "" {
		q.Set("ending_before", getAccessRequestsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
