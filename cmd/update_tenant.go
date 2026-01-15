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

	if updateTenantVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("PATCH", fullURL, strings.NewReader(updateTenantData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateTenantVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateTenantVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateTenantVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateTenantVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateTenantUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateTenantVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateTenantResponse(resp, updateTenantIncludeResp, updateTenantVerbose, updateTenantSilent)
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

func handleUpdateTenantResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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