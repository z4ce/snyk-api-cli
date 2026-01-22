package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetTenantCmd represents the get-tenant command
var GetTenantCmd = &cobra.Command{
	Use:   "get-tenant [tenant_id]",
	Short: "Get details of a specific tenant from Snyk",
	Long: `Get details of a specific tenant from the Snyk API.

This command retrieves detailed information about a specific tenant by its ID.
The tenant ID must be provided as a required argument.

Examples:
  snyk-api-cli get-tenant 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-tenant 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-tenant 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetTenant,
}

var (
	getTenantVerbose     bool
	getTenantSilent      bool
	getTenantIncludeResp bool
	getTenantUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetTenantCmd.Flags().BoolVarP(&getTenantVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetTenantCmd.Flags().BoolVarP(&getTenantSilent, "silent", "s", false, "Silent mode")
	GetTenantCmd.Flags().BoolVarP(&getTenantIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetTenantCmd.Flags().StringVarP(&getTenantUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetTenant(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetTenantURL(endpoint, version, tenantID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getTenantVerbose,
		Silent:      getTenantSilent,
		IncludeResp: getTenantIncludeResp,
		UserAgent:   getTenantUserAgent,
	})
}

func buildGetTenantURL(endpoint, version, tenantID string) (string, error) {
	// Build base URL with tenant ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s", endpoint, tenantID)

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
