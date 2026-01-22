package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteTenantMembershipCmd represents the delete-tenant-membership command
var DeleteTenantMembershipCmd = &cobra.Command{
	Use:   "delete-tenant-membership [tenant_id] [membership_id]",
	Short: "Delete an individual tenant membership for a single user from Snyk",
	Long: `Delete an individual tenant membership for a single user from the Snyk API.

This command deletes a specific tenant membership by its ID.
The tenant ID and membership ID must be provided as required arguments.

Examples:
  snyk-api-cli delete-tenant-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli delete-tenant-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli delete-tenant-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteTenantMembership,
}

var (
	deleteTenantMembershipVerbose     bool
	deleteTenantMembershipSilent      bool
	deleteTenantMembershipIncludeResp bool
	deleteTenantMembershipUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteTenantMembershipCmd.Flags().BoolVarP(&deleteTenantMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteTenantMembershipCmd.Flags().BoolVarP(&deleteTenantMembershipSilent, "silent", "s", false, "Silent mode")
	DeleteTenantMembershipCmd.Flags().BoolVarP(&deleteTenantMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteTenantMembershipCmd.Flags().StringVarP(&deleteTenantMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteTenantMembership(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	membershipID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildDeleteTenantMembershipURL(endpoint, version, tenantID, membershipID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteTenantMembershipVerbose,
		Silent:      deleteTenantMembershipSilent,
		IncludeResp: deleteTenantMembershipIncludeResp,
		UserAgent:   deleteTenantMembershipUserAgent,
	})
}

func buildDeleteTenantMembershipURL(endpoint, version, tenantID, membershipID string) (string, error) {
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
