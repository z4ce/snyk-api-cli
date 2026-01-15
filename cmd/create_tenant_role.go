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

	if createTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(createTenantRoleData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createTenantRoleVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createTenantRoleVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createTenantRoleUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createTenantRoleVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateTenantRoleResponse(resp, createTenantRoleIncludeResp, createTenantRoleVerbose, createTenantRoleSilent)
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

func handleCreateTenantRoleResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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