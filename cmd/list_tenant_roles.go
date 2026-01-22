package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListTenantRolesCmd represents the list-tenant-roles command
var ListTenantRolesCmd = &cobra.Command{
	Use:   "list-tenant-roles [tenant_id]",
	Short: "List all available roles for a given tenant from Snyk",
	Long: `List all available roles for a given tenant from the Snyk API.

This command retrieves all roles available for a specific tenant.
The tenant ID must be provided as a required argument.

Examples:
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012 --name "Admin"
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012 --custom true
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012 --assignable-by-me true
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListTenantRoles,
}

var (
	listTenantRolesVerbose        bool
	listTenantRolesSilent         bool
	listTenantRolesIncludeResp    bool
	listTenantRolesUserAgent      string
	listTenantRolesStartingAfter  string
	listTenantRolesEndingBefore   string
	listTenantRolesLimit          int
	listTenantRolesName           string
	listTenantRolesCustom         string
	listTenantRolesAssignableByMe string
)

func init() {
	// Add standard flags like other commands
	ListTenantRolesCmd.Flags().BoolVarP(&listTenantRolesVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListTenantRolesCmd.Flags().BoolVarP(&listTenantRolesSilent, "silent", "s", false, "Silent mode")
	ListTenantRolesCmd.Flags().BoolVarP(&listTenantRolesIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListTenantRolesCmd.Flags().StringVarP(&listTenantRolesUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Add pagination flags based on API spec
	ListTenantRolesCmd.Flags().StringVar(&listTenantRolesStartingAfter, "starting-after", "", "Cursor for pagination, returns results after specified point")
	ListTenantRolesCmd.Flags().StringVar(&listTenantRolesEndingBefore, "ending-before", "", "Cursor for pagination, returns results before specified point")
	ListTenantRolesCmd.Flags().IntVar(&listTenantRolesLimit, "limit", 0, "Number of results per page")

	// Add filtering flags
	ListTenantRolesCmd.Flags().StringVar(&listTenantRolesName, "name", "", "Role name filter")
	ListTenantRolesCmd.Flags().StringVar(&listTenantRolesCustom, "custom", "", "Whether role is custom (true/false)")
	ListTenantRolesCmd.Flags().StringVar(&listTenantRolesAssignableByMe, "assignable-by-me", "", "Return roles current user can assign (true/false)")
}

func runListTenantRoles(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListTenantRolesURL(endpoint, version, tenantID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listTenantRolesVerbose,
		Silent:      listTenantRolesSilent,
		IncludeResp: listTenantRolesIncludeResp,
		UserAgent:   listTenantRolesUserAgent,
	})
}

func buildListTenantRolesURL(endpoint, version, tenantID string) (string, error) {
	// Build base URL with tenant ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/roles", endpoint, tenantID)

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
	if listTenantRolesStartingAfter != "" {
		q.Set("starting_after", listTenantRolesStartingAfter)
	}
	if listTenantRolesEndingBefore != "" {
		q.Set("ending_before", listTenantRolesEndingBefore)
	}
	if listTenantRolesLimit > 0 {
		q.Set("limit", strconv.Itoa(listTenantRolesLimit))
	}

	// Add filtering parameters if specified
	if listTenantRolesName != "" {
		q.Set("name", listTenantRolesName)
	}
	if listTenantRolesCustom != "" {
		q.Set("custom", listTenantRolesCustom)
	}
	if listTenantRolesAssignableByMe != "" {
		q.Set("assignable_by_me", listTenantRolesAssignableByMe)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
