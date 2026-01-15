package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

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
	getTenantRoleVerbose           bool
	getTenantRoleSilent            bool
	getTenantRoleIncludeResp       bool
	getTenantRoleUserAgent         string
	getTenantRoleHasUsersAssigned  string
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

	if getTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getTenantRoleVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getTenantRoleVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getTenantRoleUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetTenantRoleResponse(resp, getTenantRoleIncludeResp, getTenantRoleVerbose, getTenantRoleSilent)
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

func handleGetTenantRoleResponse(resp *http.Response, includeResp, verbose, silent bool) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "* Response: %s\n", resp.Status)
	}

	// Print response headers if requested
	if includeResp {
		fmt.Printf("%s %s\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	// Read and print response body
	if !silent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		fmt.Print(string(body))
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}