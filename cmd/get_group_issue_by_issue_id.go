package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetGroupIssueByIssueIDCmd represents the get-group-issue-by-issue-id command
var GetGroupIssueByIssueIDCmd = &cobra.Command{
	Use:   "get-group-issue-by-issue-id [group_id] [issue_id]",
	Short: "Get a specific issue for a group by issue ID",
	Long: `Get a specific issue for a group by issue ID from the Snyk API.

This command retrieves detailed information about a specific issue within a group
by providing both the group ID and issue ID as required arguments.

The group ID and issue ID must be provided as UUIDs.

Examples:
  snyk-api-cli get-group-issue-by-issue-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-group-issue-by-issue-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-group-issue-by-issue-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetGroupIssueByIssueID,
}

var (
	getGroupIssueByIssueIDVerbose     bool
	getGroupIssueByIssueIDSilent      bool
	getGroupIssueByIssueIDIncludeResp bool
	getGroupIssueByIssueIDUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetGroupIssueByIssueIDCmd.Flags().BoolVarP(&getGroupIssueByIssueIDVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetGroupIssueByIssueIDCmd.Flags().BoolVarP(&getGroupIssueByIssueIDSilent, "silent", "s", false, "Silent mode")
	GetGroupIssueByIssueIDCmd.Flags().BoolVarP(&getGroupIssueByIssueIDIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetGroupIssueByIssueIDCmd.Flags().StringVarP(&getGroupIssueByIssueIDUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetGroupIssueByIssueID(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	issueID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetGroupIssueByIssueIDURL(endpoint, version, groupID, issueID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getGroupIssueByIssueIDVerbose,
		Silent:      getGroupIssueByIssueIDSilent,
		IncludeResp: getGroupIssueByIssueIDIncludeResp,
		UserAgent:   getGroupIssueByIssueIDUserAgent,
	})
}

func buildGetGroupIssueByIssueIDURL(endpoint, version, groupID, issueID string) (string, error) {
	// Build base URL with group ID and issue ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/issues/%s", endpoint, groupID, issueID)

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
