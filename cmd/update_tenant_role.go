package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateTenantRoleCmd represents the update-tenant-role command
var UpdateTenantRoleCmd = &cobra.Command{
	Use:   "update-tenant-role [tenant_id] [role_id]",
	Short: "Update a specific tenant role by its id and its tenant id in Snyk",
	Long: `Update a specific tenant role by its id and its tenant id in the Snyk API.

This command allows you to update a specific tenant role by its ID.
The tenant ID and role ID must be provided as required arguments.

Examples:
  snyk-api-cli update-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --data '{"data":{"attributes":{"name":"Updated Role","description":"Updated description","permissions":["tenant.read","tenant.write"]},"id":"87654321-4321-4321-4321-210987654321","type":"tenant_role"}}'
  snyk-api-cli update-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --data @role.json
  snyk-api-cli update-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --data '...' --force true
  snyk-api-cli update-tenant-role 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --data '...' --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateTenantRole,
}

var (
	updateTenantRoleVerbose     bool
	updateTenantRoleSilent      bool
	updateTenantRoleIncludeResp bool
	updateTenantRoleUserAgent   string
	updateTenantRoleData        string
	updateTenantRoleForce       string
)

func init() {
	// Add standard flags like other commands
	UpdateTenantRoleCmd.Flags().BoolVarP(&updateTenantRoleVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateTenantRoleCmd.Flags().BoolVarP(&updateTenantRoleSilent, "silent", "s", false, "Silent mode")
	UpdateTenantRoleCmd.Flags().BoolVarP(&updateTenantRoleIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateTenantRoleCmd.Flags().StringVarP(&updateTenantRoleUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	UpdateTenantRoleCmd.Flags().StringVarP(&updateTenantRoleData, "data", "d", "", "JSON data to send in request body")
	UpdateTenantRoleCmd.Flags().StringVar(&updateTenantRoleForce, "force", "", "Boolean flag to update role with assigned users (true/false)")
}

func runUpdateTenantRole(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	roleID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate required data
	if updateTenantRoleData == "" {
		return fmt.Errorf("request body data is required (use --data)")
	}

	// Build the URL
	fullURL, err := buildUpdateTenantRoleURL(endpoint, version, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        updateTenantRoleData,
		Verbose:     updateTenantRoleVerbose,
		Silent:      updateTenantRoleSilent,
		IncludeResp: updateTenantRoleIncludeResp,
		UserAgent:   updateTenantRoleUserAgent,
	})
}

func buildUpdateTenantRoleURL(endpoint, version, tenantID, roleID string) (string, error) {
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

	// Add optional force parameter if specified
	if updateTenantRoleForce != "" {
		q.Set("force", updateTenantRoleForce)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
