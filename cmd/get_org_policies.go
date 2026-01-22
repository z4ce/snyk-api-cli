package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetOrgPoliciesCmd represents the get-org-policies command
var GetOrgPoliciesCmd = &cobra.Command{
	Use:   "get-org-policies [org_id]",
	Short: "List organization-level policies from Snyk",
	Long: `List organization-level policies from the Snyk API for a specific organization.

This command retrieves a list of organization-level policies that the authenticated user can access
within the specified organization. The results can be filtered, searched, and paginated using various
query parameters.

Note: Organization-level Policy APIs are only available for Code Consistent Ignores.

Examples:
  snyk-api-cli get-org-policies 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-org-policies 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli get-org-policies 12345678-1234-1234-1234-123456789012 --search "security"
  snyk-api-cli get-org-policies 12345678-1234-1234-1234-123456789012 --order-by created --order-direction desc
  snyk-api-cli get-org-policies 12345678-1234-1234-1234-123456789012 --expires-never true
  snyk-api-cli get-org-policies 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli get-org-policies 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runGetOrgPolicies,
}

var (
	getOrgPoliciesSearch         string
	getOrgPoliciesOrderBy        string
	getOrgPoliciesOrderDirection string
	getOrgPoliciesReview         string
	getOrgPoliciesExpiresBefore  string
	getOrgPoliciesExpiresAfter   string
	getOrgPoliciesExpiresNever   bool
	getOrgPoliciesLimit          int
	getOrgPoliciesStartingAfter  string
	getOrgPoliciesEndingBefore   string
	getOrgPoliciesVerbose        bool
	getOrgPoliciesSilent         bool
	getOrgPoliciesIncludeResp    bool
	getOrgPoliciesUserAgent      string
)

func init() {
	// Add flags for query parameters
	GetOrgPoliciesCmd.Flags().StringVar(&getOrgPoliciesSearch, "search", "", "Keyword for searching policy fields")
	GetOrgPoliciesCmd.Flags().StringVar(&getOrgPoliciesOrderBy, "order-by", "", "Column to sort on (created, expires)")
	GetOrgPoliciesCmd.Flags().StringVar(&getOrgPoliciesOrderDirection, "order-direction", "", "Sorting direction (asc, desc)")
	GetOrgPoliciesCmd.Flags().StringVar(&getOrgPoliciesReview, "review", "", "Policy rule review state")
	GetOrgPoliciesCmd.Flags().StringVar(&getOrgPoliciesExpiresBefore, "expires-before", "", "Select policies expiring before a time (RFC3339 format)")
	GetOrgPoliciesCmd.Flags().StringVar(&getOrgPoliciesExpiresAfter, "expires-after", "", "Select policies expiring after a time (RFC3339 format)")
	GetOrgPoliciesCmd.Flags().BoolVar(&getOrgPoliciesExpiresNever, "expires-never", false, "Select policies that never expire")
	GetOrgPoliciesCmd.Flags().IntVar(&getOrgPoliciesLimit, "limit", 0, "Number of results per page")
	GetOrgPoliciesCmd.Flags().StringVar(&getOrgPoliciesStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetOrgPoliciesCmd.Flags().StringVar(&getOrgPoliciesEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	GetOrgPoliciesCmd.Flags().BoolVarP(&getOrgPoliciesVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgPoliciesCmd.Flags().BoolVarP(&getOrgPoliciesSilent, "silent", "s", false, "Silent mode")
	GetOrgPoliciesCmd.Flags().BoolVarP(&getOrgPoliciesIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgPoliciesCmd.Flags().StringVarP(&getOrgPoliciesUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOrgPolicies(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetOrgPoliciesURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getOrgPoliciesVerbose,
		Silent:      getOrgPoliciesSilent,
		IncludeResp: getOrgPoliciesIncludeResp,
		UserAgent:   getOrgPoliciesUserAgent,
	})
}

func buildGetOrgPoliciesURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/policies", endpoint, orgID)

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
	if getOrgPoliciesSearch != "" {
		q.Set("search", getOrgPoliciesSearch)
	}
	if getOrgPoliciesOrderBy != "" {
		q.Set("order_by", getOrgPoliciesOrderBy)
	}
	if getOrgPoliciesOrderDirection != "" {
		q.Set("order_direction", getOrgPoliciesOrderDirection)
	}
	if getOrgPoliciesReview != "" {
		q.Set("review", getOrgPoliciesReview)
	}
	if getOrgPoliciesExpiresBefore != "" {
		q.Set("expires_before", getOrgPoliciesExpiresBefore)
	}
	if getOrgPoliciesExpiresAfter != "" {
		q.Set("expires_after", getOrgPoliciesExpiresAfter)
	}
	if getOrgPoliciesExpiresNever {
		q.Set("expires_never", "true")
	}
	if getOrgPoliciesLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getOrgPoliciesLimit))
	}
	if getOrgPoliciesStartingAfter != "" {
		q.Set("starting_after", getOrgPoliciesStartingAfter)
	}
	if getOrgPoliciesEndingBefore != "" {
		q.Set("ending_before", getOrgPoliciesEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
