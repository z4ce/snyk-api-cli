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

	if updateTenantMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("PATCH", fullURL, strings.NewReader(updateTenantMembershipData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateTenantMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateTenantMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateTenantMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateTenantMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateTenantMembershipUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateTenantMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateTenantMembershipResponse(resp, updateTenantMembershipIncludeResp, updateTenantMembershipVerbose, updateTenantMembershipSilent)
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

func handleUpdateTenantMembershipResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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