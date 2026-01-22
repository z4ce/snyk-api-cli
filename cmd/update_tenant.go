package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateTenantCmd represents the update-tenant command
var UpdateTenantCmd = &cobra.Command{
	Use:   "update-tenant [tenant_id]",
	Short: "Update a specific tenant in Snyk",
	Long: `Update a specific tenant in the Snyk API.

This command allows you to update the details of a specific tenant by its ID.
The tenant ID must be provided as a required argument.

Examples:
  snyk-api-cli update-tenant 12345678-1234-1234-1234-123456789012 --data '{"data":{"attributes":{"name":"New Tenant Name"},"id":"12345678-1234-1234-1234-123456789012","type":"tenant"}}'
  snyk-api-cli update-tenant 12345678-1234-1234-1234-123456789012 --data @tenant.json
  snyk-api-cli update-tenant 12345678-1234-1234-1234-123456789012 --data '{"data":{"attributes":{"name":"Updated Name"},"id":"12345678-1234-1234-1234-123456789012","type":"tenant"}}' --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runUpdateTenant,
}

var (
	updateTenantVerbose     bool
	updateTenantSilent      bool
	updateTenantIncludeResp bool
	updateTenantUserAgent   string
	updateTenantData        string
)

func init() {
	// Add standard flags like other commands
	UpdateTenantCmd.Flags().BoolVarP(&updateTenantVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateTenantCmd.Flags().BoolVarP(&updateTenantSilent, "silent", "s", false, "Silent mode")
	UpdateTenantCmd.Flags().BoolVarP(&updateTenantIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateTenantCmd.Flags().StringVarP(&updateTenantUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	UpdateTenantCmd.Flags().StringVarP(&updateTenantData, "data", "d", "", "JSON data to send in request body")
}

func runUpdateTenant(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate required data
	if updateTenantData == "" {
		return fmt.Errorf("request body data is required (use --data)")
	}

	// Build the URL
	fullURL, err := buildUpdateTenantURL(endpoint, version, tenantID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        updateTenantData,
		Verbose:     updateTenantVerbose,
		Silent:      updateTenantSilent,
		IncludeResp: updateTenantIncludeResp,
		UserAgent:   updateTenantUserAgent,
	})
}

func buildUpdateTenantURL(endpoint, version, tenantID string) (string, error) {
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
