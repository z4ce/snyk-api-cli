package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListTenantsCmd represents the list-tenants command
var ListTenantsCmd = &cobra.Command{
	Use:   "list-tenants",
	Short: "Get a list of all accessible tenants from Snyk",
	Long: `Get a list of all accessible tenants from the Snyk API.

This command retrieves a list of all tenants that the authenticated user has access to.
It supports pagination through cursor-based pagination and allows filtering results.

Examples:
  snyk-api-cli list-tenants
  snyk-api-cli list-tenants --limit 10
  snyk-api-cli list-tenants --starting-after abc123
  snyk-api-cli list-tenants --ending-before xyz789
  snyk-api-cli list-tenants --verbose`,
	RunE: runListTenants,
}

var (
	listTenantsVerbose       bool
	listTenantsSilent        bool
	listTenantsIncludeResp   bool
	listTenantsUserAgent     string
	listTenantsStartingAfter string
	listTenantsEndingBefore  string
	listTenantsLimit         int
)

func init() {
	// Add standard flags like other commands
	ListTenantsCmd.Flags().BoolVarP(&listTenantsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListTenantsCmd.Flags().BoolVarP(&listTenantsSilent, "silent", "s", false, "Silent mode")
	ListTenantsCmd.Flags().BoolVarP(&listTenantsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListTenantsCmd.Flags().StringVarP(&listTenantsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Add pagination flags based on API spec
	ListTenantsCmd.Flags().StringVar(&listTenantsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after specified point")
	ListTenantsCmd.Flags().StringVar(&listTenantsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before specified point")
	ListTenantsCmd.Flags().IntVar(&listTenantsLimit, "limit", 0, "Number of results per page")
}

func runListTenants(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListTenantsURL(endpoint, version, listTenantsStartingAfter, listTenantsEndingBefore, listTenantsLimit)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listTenantsVerbose,
		Silent:      listTenantsSilent,
		IncludeResp: listTenantsIncludeResp,
		UserAgent:   listTenantsUserAgent,
	})
}

func buildListTenantsURL(endpoint, version, startingAfter, endingBefore string, limit int) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/tenants", endpoint)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add pagination parameters if specified
	if startingAfter != "" {
		q.Set("starting_after", startingAfter)
	}
	if endingBefore != "" {
		q.Set("ending_before", endingBefore)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
