package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateTenantMembershipCmd represents the update-tenant-membership command
var UpdateTenantMembershipCmd = &cobra.Command{
	Use:   "update-tenant-membership [tenant_id] [membership_id]",
	Short: "Update a tenant membership in Snyk",
	Long: `Update a tenant membership in the Snyk API.

This command allows you to update a specific tenant membership by its ID.
The tenant ID and membership ID must be provided as required arguments.

Examples:
  snyk-api-cli update-tenant-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --data '{"data":{"attributes":{},"id":"87654321-4321-4321-4321-210987654321","relationships":{"role":{"data":{"id":"role-uuid","type":"role"}}},"type":"tenant_membership"}}'
  snyk-api-cli update-tenant-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --data @membership.json
  snyk-api-cli update-tenant-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --data '...' --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateTenantMembership,
}

var (
	updateTenantMembershipVerbose     bool
	updateTenantMembershipSilent      bool
	updateTenantMembershipIncludeResp bool
	updateTenantMembershipUserAgent   string
	updateTenantMembershipData        string
)

func init() {
	// Add standard flags like other commands
	UpdateTenantMembershipCmd.Flags().BoolVarP(&updateTenantMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateTenantMembershipCmd.Flags().BoolVarP(&updateTenantMembershipSilent, "silent", "s", false, "Silent mode")
	UpdateTenantMembershipCmd.Flags().BoolVarP(&updateTenantMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateTenantMembershipCmd.Flags().StringVarP(&updateTenantMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	UpdateTenantMembershipCmd.Flags().StringVarP(&updateTenantMembershipData, "data", "d", "", "JSON data to send in request body")
}

func runUpdateTenantMembership(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	membershipID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate required data
	if updateTenantMembershipData == "" {
		return fmt.Errorf("request body data is required (use --data)")
	}

	// Build the URL
	fullURL, err := buildUpdateTenantMembershipURL(endpoint, version, tenantID, membershipID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        updateTenantMembershipData,
		Verbose:     updateTenantMembershipVerbose,
		Silent:      updateTenantMembershipSilent,
		IncludeResp: updateTenantMembershipIncludeResp,
		UserAgent:   updateTenantMembershipUserAgent,
	})
}

func buildUpdateTenantMembershipURL(endpoint, version, tenantID, membershipID string) (string, error) {
	// Build base URL with tenant ID and membership ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/memberships/%s", endpoint, tenantID, membershipID)

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
