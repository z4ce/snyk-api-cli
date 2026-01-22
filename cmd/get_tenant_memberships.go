package cmd

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetTenantMembershipsCmd represents the get-tenant-memberships command
var GetTenantMembershipsCmd = &cobra.Command{
	Use:   "get-tenant-memberships [tenant_id]",
	Short: "Get all memberships of a tenant from Snyk",
	Long: `Get all memberships of a tenant from the Snyk API.

This command retrieves all memberships for a specific tenant.
The tenant ID must be provided as a required argument.

Examples:
  snyk-api-cli get-tenant-memberships 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-tenant-memberships 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli get-tenant-memberships 12345678-1234-1234-1234-123456789012 --sort-by username
  snyk-api-cli get-tenant-memberships 12345678-1234-1234-1234-123456789012 --sort-order DESC
  snyk-api-cli get-tenant-memberships 12345678-1234-1234-1234-123456789012 --email user@example.com
  snyk-api-cli get-tenant-memberships 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runGetTenantMemberships,
}

var (
	getTenantMembershipsVerbose        bool
	getTenantMembershipsSilent         bool
	getTenantMembershipsIncludeResp    bool
	getTenantMembershipsUserAgent      string
	getTenantMembershipsStartingAfter  string
	getTenantMembershipsEndingBefore   string
	getTenantMembershipsLimit          int
	getTenantMembershipsSortBy         string
	getTenantMembershipsSortOrder      string
	getTenantMembershipsEmail          string
	getTenantMembershipsUserID         string
	getTenantMembershipsName           string
	getTenantMembershipsUsername       string
	getTenantMembershipsConnectionType string
	getTenantMembershipsRoleName       string
)

func init() {
	// Add standard flags like other commands
	GetTenantMembershipsCmd.Flags().BoolVarP(&getTenantMembershipsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetTenantMembershipsCmd.Flags().BoolVarP(&getTenantMembershipsSilent, "silent", "s", false, "Silent mode")
	GetTenantMembershipsCmd.Flags().BoolVarP(&getTenantMembershipsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetTenantMembershipsCmd.Flags().StringVarP(&getTenantMembershipsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Add pagination flags based on API spec
	GetTenantMembershipsCmd.Flags().StringVar(&getTenantMembershipsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after specified point")
	GetTenantMembershipsCmd.Flags().StringVar(&getTenantMembershipsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before specified point")
	GetTenantMembershipsCmd.Flags().IntVar(&getTenantMembershipsLimit, "limit", 0, "Number of results per page")

	// Add sorting flags
	GetTenantMembershipsCmd.Flags().StringVar(&getTenantMembershipsSortBy, "sort-by", "", "Column to sort results by (username, user_display_name, email, etc.)")
	GetTenantMembershipsCmd.Flags().StringVar(&getTenantMembershipsSortOrder, "sort-order", "", "Sort direction (ASC or DESC)")

	// Add filtering flags
	GetTenantMembershipsCmd.Flags().StringVar(&getTenantMembershipsEmail, "email", "", "Filter by email address")
	GetTenantMembershipsCmd.Flags().StringVar(&getTenantMembershipsUserID, "user-id", "", "Filter by user ID")
	GetTenantMembershipsCmd.Flags().StringVar(&getTenantMembershipsName, "name", "", "Filter by name")
	GetTenantMembershipsCmd.Flags().StringVar(&getTenantMembershipsUsername, "username", "", "Filter by username")
	GetTenantMembershipsCmd.Flags().StringVar(&getTenantMembershipsConnectionType, "connection-type", "", "Filter by connection type")
	GetTenantMembershipsCmd.Flags().StringVar(&getTenantMembershipsRoleName, "role-name", "", "Filter by role name")
}

func runGetTenantMemberships(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetTenantMembershipsURL(endpoint, version, tenantID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getTenantMembershipsVerbose,
		Silent:      getTenantMembershipsSilent,
		IncludeResp: getTenantMembershipsIncludeResp,
		UserAgent:   getTenantMembershipsUserAgent,
	})
}

func buildGetTenantMembershipsURL(endpoint, version, tenantID string) (string, error) {
	// Build base URL with tenant ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/memberships", endpoint, tenantID)

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
	if getTenantMembershipsStartingAfter != "" {
		q.Set("starting_after", getTenantMembershipsStartingAfter)
	}
	if getTenantMembershipsEndingBefore != "" {
		q.Set("ending_before", getTenantMembershipsEndingBefore)
	}
	if getTenantMembershipsLimit > 0 {
		q.Set("limit", strconv.Itoa(getTenantMembershipsLimit))
	}

	// Add sorting parameters if specified
	if getTenantMembershipsSortBy != "" {
		q.Set("sort_by", getTenantMembershipsSortBy)
	}
	if getTenantMembershipsSortOrder != "" {
		q.Set("sort_order", getTenantMembershipsSortOrder)
	}

	// Add filtering parameters if specified
	if getTenantMembershipsEmail != "" {
		q.Set("email", getTenantMembershipsEmail)
	}
	if getTenantMembershipsUserID != "" {
		q.Set("user_id", getTenantMembershipsUserID)
	}
	if getTenantMembershipsName != "" {
		q.Set("name", getTenantMembershipsName)
	}
	if getTenantMembershipsUsername != "" {
		q.Set("username", getTenantMembershipsUsername)
	}
	if getTenantMembershipsConnectionType != "" {
		q.Set("connection_type", getTenantMembershipsConnectionType)
	}
	if getTenantMembershipsRoleName != "" {
		q.Set("role_name", getTenantMembershipsRoleName)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
