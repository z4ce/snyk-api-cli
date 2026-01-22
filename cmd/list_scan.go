package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListScanCmd represents the list-scan command
var ListScanCmd = &cobra.Command{
	Use:   "list-scan [org_id]",
	Short: "List cloud scans for an organization",
	Long: `List cloud scans for an organization from the Snyk API.

This command retrieves a list of cloud scans for the specified organization.
The results can be paginated using various query parameters.

Examples:
  snyk-api-cli list-scan 9a46d918-8764-458c-1234-0987abcd6543
  snyk-api-cli list-scan 9a46d918-8764-458c-1234-0987abcd6543 --limit 10
  snyk-api-cli list-scan 9a46d918-8764-458c-1234-0987abcd6543 --starting-after abc123
  snyk-api-cli list-scan 9a46d918-8764-458c-1234-0987abcd6543 --ending-before xyz789
  snyk-api-cli list-scan 9a46d918-8764-458c-1234-0987abcd6543 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListScan,
}

var (
	listScanStartingAfter string
	listScanEndingBefore  string
	listScanLimit         int
	listScanVerbose       bool
	listScanSilent        bool
	listScanIncludeResp   bool
	listScanUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListScanCmd.Flags().StringVar(&listScanStartingAfter, "starting-after", "", "Pagination cursor for results after this point")
	ListScanCmd.Flags().StringVar(&listScanEndingBefore, "ending-before", "", "Pagination cursor for results before this point")
	ListScanCmd.Flags().IntVar(&listScanLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	ListScanCmd.Flags().BoolVarP(&listScanVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListScanCmd.Flags().BoolVarP(&listScanSilent, "silent", "s", false, "Silent mode")
	ListScanCmd.Flags().BoolVarP(&listScanIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListScanCmd.Flags().StringVarP(&listScanUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListScan(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListScanURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listScanVerbose,
		Silent:      listScanSilent,
		IncludeResp: listScanIncludeResp,
		UserAgent:   listScanUserAgent,
	})
}

func buildListScanURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL with org_id path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/scans", endpoint, orgID)

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
	if listScanStartingAfter != "" {
		q.Set("starting_after", listScanStartingAfter)
	}
	if listScanEndingBefore != "" {
		q.Set("ending_before", listScanEndingBefore)
	}
	if listScanLimit > 0 {
		q.Set("limit", strconv.Itoa(listScanLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
