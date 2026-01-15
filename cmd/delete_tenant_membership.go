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

	if deleteTenantMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteTenantMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteTenantMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteTenantMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteTenantMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteTenantMembershipUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteTenantMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteTenantMembershipResponse(resp, deleteTenantMembershipIncludeResp, deleteTenantMembershipVerbose, deleteTenantMembershipSilent)
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

func handleDeleteTenantMembershipResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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