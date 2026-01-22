package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetOrgIssueCmd represents the get-org-issue command
var GetOrgIssueCmd = &cobra.Command{
	Use:   "get-org-issue [org_id] [issue_id]",
	Short: "Get a specific issue for an organization by issue ID",
	Long: `Get a specific issue for an organization by issue ID from the Snyk API.

This command retrieves detailed information about a specific issue within an organization
by providing both the organization ID and issue ID as required arguments.

The organization ID and issue ID must be provided as UUIDs.

Required permissions:
- View Organization (org.read)
- View Projects (org.project.read)
- View Project history (org.project.snapshot.read)

Examples:
  snyk-api-cli get-org-issue 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-org-issue 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-org-issue 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetOrgIssue,
}

var (
	getOrgIssueVerbose     bool
	getOrgIssueSilent      bool
	getOrgIssueIncludeResp bool
	getOrgIssueUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetOrgIssueCmd.Flags().BoolVarP(&getOrgIssueVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgIssueCmd.Flags().BoolVarP(&getOrgIssueSilent, "silent", "s", false, "Silent mode")
	GetOrgIssueCmd.Flags().BoolVarP(&getOrgIssueIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgIssueCmd.Flags().StringVarP(&getOrgIssueUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOrgIssue(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	issueID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetOrgIssueURL(endpoint, version, orgID, issueID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getOrgIssueVerbose,
		Silent:      getOrgIssueSilent,
		IncludeResp: getOrgIssueIncludeResp,
		UserAgent:   getOrgIssueUserAgent,
	})
}

func buildGetOrgIssueURL(endpoint, version, orgID, issueID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(issueID) == "" {
		return "", fmt.Errorf("issue_id cannot be empty")
	}

	// Build base URL with organization ID and issue ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/issues/%s", endpoint, orgID, issueID)

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
