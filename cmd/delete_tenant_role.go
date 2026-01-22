package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteTenantRoleCmd represents the delete-tenant-role command
var DeleteTenantRoleCmd = &cobra.Command{
	Use:   "delete-tenant-role [tenant_id] [role_id]",
	Short: "Delete a specific tenant role by its id and its tenant id from Snyk",
	Long: `Delete a specific tenant role by its id and its tenant id from the Snyk API.

This command deletes a specific custom tenant role by its ID.
The tenant ID and role ID must be provided as required arguments.

Examples:
  snyk-api-cli delete-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli delete-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli delete-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteTenantRole,
}

var (
	deleteTenantRoleVerbose     bool
	deleteTenantRoleSilent      bool
	deleteTenantRoleIncludeResp bool
	deleteTenantRoleUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteTenantRoleCmd.Flags().BoolVarP(&deleteTenantRoleVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteTenantRoleCmd.Flags().BoolVarP(&deleteTenantRoleSilent, "silent", "s", false, "Silent mode")
	DeleteTenantRoleCmd.Flags().BoolVarP(&deleteTenantRoleIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteTenantRoleCmd.Flags().StringVarP(&deleteTenantRoleUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteTenantRole(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	roleID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildDeleteTenantRoleURL(endpoint, version, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteTenantRoleVerbose,
		Silent:      deleteTenantRoleSilent,
		IncludeResp: deleteTenantRoleIncludeResp,
		UserAgent:   deleteTenantRoleUserAgent,
	})
}

func buildDeleteTenantRoleURL(endpoint, version, tenantID, roleID string) (string, error) {
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

	u.RawQuery = q.Encode()
	return u.String(), nil
}
