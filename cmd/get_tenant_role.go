package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetTenantRoleCmd represents the get-tenant-role command
var GetTenantRoleCmd = &cobra.Command{
	Use:   "get-tenant-role [tenant_id] [role_id]",
	Short: "Return a specific role by its id and its tenant id from Snyk",
	Long: `Return a specific role by its id and its tenant id from the Snyk API.

This command retrieves details about a specific role within a tenant.
The tenant ID and role ID must be provided as required arguments.

Examples:
  snyk-api-cli get-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --has-users-assigned true
  snyk-api-cli get-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetTenantRole,
}

var (
	getTenantRoleVerbose          bool
	getTenantRoleSilent           bool
	getTenantRoleIncludeResp      bool
	getTenantRoleUserAgent        string
	getTenantRoleHasUsersAssigned string
)

func init() {
	// Add standard flags like other commands
	GetTenantRoleCmd.Flags().BoolVarP(&getTenantRoleVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetTenantRoleCmd.Flags().BoolVarP(&getTenantRoleSilent, "silent", "s", false, "Silent mode")
	GetTenantRoleCmd.Flags().BoolVarP(&getTenantRoleIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetTenantRoleCmd.Flags().StringVarP(&getTenantRoleUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Add optional parameter based on API spec
	GetTenantRoleCmd.Flags().StringVar(&getTenantRoleHasUsersAssigned, "has-users-assigned", "", "Boolean to return current role memberships (true/false)")
}

func runGetTenantRole(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	roleID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetTenantRoleURL(endpoint, version, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getTenantRoleVerbose,
		Silent:      getTenantRoleSilent,
		IncludeResp: getTenantRoleIncludeResp,
		UserAgent:   getTenantRoleUserAgent,
	})
}

func buildGetTenantRoleURL(endpoint, version, tenantID, roleID string) (string, error) {
	// Build base URL with tenant ID and role ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/roles/%s", endpoint, tenantID, roleID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional parameter if specified
	if getTenantRoleHasUsersAssigned != "" {
		q.Set("has_users_assigned", getTenantRoleHasUsersAssigned)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
