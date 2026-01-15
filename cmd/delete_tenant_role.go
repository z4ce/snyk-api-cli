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

	if deleteTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteTenantRoleVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteTenantRoleVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteTenantRoleUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteTenantRoleResponse(resp, deleteTenantRoleIncludeResp, deleteTenantRoleVerbose, deleteTenantRoleSilent)
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

func handleDeleteTenantRoleResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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
		// Only print body if it's not empty (204 No Content responses have no body)
		if len(body) > 0 {
			fmt.Print(string(body))
		}
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}