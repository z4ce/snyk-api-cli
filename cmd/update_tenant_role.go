package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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

	if updateTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("PATCH", fullURL, strings.NewReader(updateTenantRoleData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateTenantRoleVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateTenantRoleVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateTenantRoleUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateTenantRoleResponse(resp, updateTenantRoleIncludeResp, updateTenantRoleVerbose, updateTenantRoleSilent)
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

func handleUpdateTenantRoleResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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