package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateTenantRoleCmd represents the create-tenant-role command
var CreateTenantRoleCmd = &cobra.Command{
	Use:   "create-tenant-role [tenant_id]",
	Short: "Create a custom tenant role for a given tenant in Snyk",
	Long: `Create a custom tenant role for a given tenant in the Snyk API.

This command creates a new custom role for a specific tenant.
The tenant ID must be provided as a required argument.

Examples:
  snyk-api-cli create-tenant-role 12345678-1234-1234-1234-123456789012 --data '{"data":{"attributes":{"name":"Custom Role","description":"A custom role","permissions":["tenant.read","tenant.write"]},"type":"tenant_role"}}'
  snyk-api-cli create-tenant-role 12345678-1234-1234-1234-123456789012 --data @role.json
  snyk-api-cli create-tenant-role 12345678-1234-1234-1234-123456789012 --data '{"data":{"attributes":{"name":"Manager","description":"Manager role","permissions":["tenant.read","tenant.membership.read"]},"type":"tenant_role"}}' --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateTenantRole,
}

var (
	createTenantRoleVerbose     bool
	createTenantRoleSilent      bool
	createTenantRoleIncludeResp bool
	createTenantRoleUserAgent   string
	createTenantRoleData        string
)

func init() {
	// Add standard flags like other commands
	CreateTenantRoleCmd.Flags().BoolVarP(&createTenantRoleVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateTenantRoleCmd.Flags().BoolVarP(&createTenantRoleSilent, "silent", "s", false, "Silent mode")
	CreateTenantRoleCmd.Flags().BoolVarP(&createTenantRoleIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateTenantRoleCmd.Flags().StringVarP(&createTenantRoleUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	CreateTenantRoleCmd.Flags().StringVarP(&createTenantRoleData, "data", "d", "", "JSON data to send in request body")
}

func runCreateTenantRole(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate required data
	if createTenantRoleData == "" {
		return fmt.Errorf("request body data is required (use --data)")
	}

	// Build the URL
	fullURL, err := buildCreateTenantRoleURL(endpoint, version, tenantID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        createTenantRoleData,
		ContentType: "application/vnd.api+json",
		Verbose:     createTenantRoleVerbose,
		Silent:      createTenantRoleSilent,
		IncludeResp: createTenantRoleIncludeResp,
		UserAgent:   createTenantRoleUserAgent,
	})
}

func buildCreateTenantRoleURL(endpoint, version, tenantID string) (string, error) {
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

	u.RawQuery = q.Encode()
	return u.String(), nil
}
