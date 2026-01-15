package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

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
	getOrgPoliciesSearch          string
	getOrgPoliciesOrderBy         string
	getOrgPoliciesOrderDirection  string
	getOrgPoliciesReview          string
	getOrgPoliciesExpiresBefore   string
	getOrgPoliciesExpiresAfter    string
	getOrgPoliciesExpiresNever    bool
	getOrgPoliciesLimit           int
	getOrgPoliciesStartingAfter   string
	getOrgPoliciesEndingBefore    string
	getOrgPoliciesVerbose         bool
	getOrgPoliciesSilent          bool
	getOrgPoliciesIncludeResp     bool
	getOrgPoliciesUserAgent       string
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

	if getOrgPoliciesVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getOrgPoliciesVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getOrgPoliciesVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getOrgPoliciesVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getOrgPoliciesVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getOrgPoliciesUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getOrgPoliciesVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetOrgPoliciesResponse(resp, getOrgPoliciesIncludeResp, getOrgPoliciesVerbose, getOrgPoliciesSilent)
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

func handleGetOrgPoliciesResponse(resp *http.Response, includeResp, verbose, silent bool) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "* Response: %s\n", resp.Status)
	}

	// Print response headers if requested
	if includeResp {
		fmt.Printf("%s %s\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	// Read and print response body
	if !silent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		fmt.Print(string(body))
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}