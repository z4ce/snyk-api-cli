package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListOrgAssignmentsCmd represents the list-org-assignments command
var ListOrgAssignmentsCmd = &cobra.Command{
	Use:   "list-org-assignments [org_id]",
	Short: "Retrieve a list of assignments for an organization",
	Long: `Retrieve a list of assignments for an organization from the Snyk Learn API.

This command retrieves a list of learn assignments that have been created for users
within the specified organization. The results can be paginated using various
query parameters.

Examples:
  snyk-api-cli list-org-assignments 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-org-assignments 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-org-assignments 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli list-org-assignments 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli list-org-assignments 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListOrgAssignments,
}

var (
	listOrgAssignmentsLimit         int
	listOrgAssignmentsStartingAfter string
	listOrgAssignmentsEndingBefore  string
	listOrgAssignmentsVerbose       bool
	listOrgAssignmentsSilent        bool
	listOrgAssignmentsIncludeResp   bool
	listOrgAssignmentsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListOrgAssignmentsCmd.Flags().IntVar(&listOrgAssignmentsLimit, "limit", 0, "Number of results per page")
	ListOrgAssignmentsCmd.Flags().StringVar(&listOrgAssignmentsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListOrgAssignmentsCmd.Flags().StringVar(&listOrgAssignmentsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	ListOrgAssignmentsCmd.Flags().BoolVarP(&listOrgAssignmentsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgAssignmentsCmd.Flags().BoolVarP(&listOrgAssignmentsSilent, "silent", "s", false, "Silent mode")
	ListOrgAssignmentsCmd.Flags().BoolVarP(&listOrgAssignmentsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgAssignmentsCmd.Flags().StringVarP(&listOrgAssignmentsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgAssignments(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgAssignmentsURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listOrgAssignmentsVerbose,
		Silent:      listOrgAssignmentsSilent,
		IncludeResp: listOrgAssignmentsIncludeResp,
		UserAgent:   listOrgAssignmentsUserAgent,
	})
}

func buildListOrgAssignmentsURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/learn/assignments", endpoint, orgID)

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
	if listOrgAssignmentsLimit > 0 {
		q.Set("limit", strconv.Itoa(listOrgAssignmentsLimit))
	}
	if listOrgAssignmentsStartingAfter != "" {
		q.Set("starting_after", listOrgAssignmentsStartingAfter)
	}
	if listOrgAssignmentsEndingBefore != "" {
		q.Set("ending_before", listOrgAssignmentsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
