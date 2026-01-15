package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListTenantRolesCmd represents the list-tenant-roles command
var ListTenantRolesCmd = &cobra.Command{
	Use:   "list-tenant-roles [tenant_id]",
	Short: "List all available roles for a given tenant from Snyk",
	Long: `List all available roles for a given tenant from the Snyk API.

This command retrieves all roles available for a specific tenant.
The tenant ID must be provided as a required argument.

Examples:
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012 --name "Admin"
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012 --custom true
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012 --assignable-by-me true
  snyk-api-cli list-tenant-roles 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListTenantRoles,
}

var (
	listTenantRolesVerbose          bool
	listTenantRolesSilent           bool
	listTenantRolesIncludeResp      bool
	listTenantRolesUserAgent        string
	listTenantRolesStartingAfter    string
	listTenantRolesEndingBefore     string
	listTenantRolesLimit            int
	listTenantRolesName             string
	listTenantRolesCustom           string
	listTenantRolesAssignableByMe   string
)

func init() {
	// Add standard flags like other commands
	ListTenantRolesCmd.Flags().BoolVarP(&listTenantRolesVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListTenantRolesCmd.Flags().BoolVarP(&listTenantRolesSilent, "silent", "s", false, "Silent mode")
	ListTenantRolesCmd.Flags().BoolVarP(&listTenantRolesIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListTenantRolesCmd.Flags().StringVarP(&listTenantRolesUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Add pagination flags based on API spec
	ListTenantRolesCmd.Flags().StringVar(&listTenantRolesStartingAfter, "starting-after", "", "Cursor for pagination, returns results after specified point")
	ListTenantRolesCmd.Flags().StringVar(&listTenantRolesEndingBefore, "ending-before", "", "Cursor for pagination, returns results before specified point")
	ListTenantRolesCmd.Flags().IntVar(&listTenantRolesLimit, "limit", 0, "Number of results per page")
	
	// Add filtering flags
	ListTenantRolesCmd.Flags().StringVar(&listTenantRolesName, "name", "", "Role name filter")
	ListTenantRolesCmd.Flags().StringVar(&listTenantRolesCustom, "custom", "", "Whether role is custom (true/false)")
	ListTenantRolesCmd.Flags().StringVar(&listTenantRolesAssignableByMe, "assignable-by-me", "", "Return roles current user can assign (true/false)")
}

func runListTenantRoles(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListTenantRolesURL(endpoint, version, tenantID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listTenantRolesVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listTenantRolesVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listTenantRolesVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listTenantRolesVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listTenantRolesVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listTenantRolesUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listTenantRolesVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListTenantRolesResponse(resp, listTenantRolesIncludeResp, listTenantRolesVerbose, listTenantRolesSilent)
}

func buildListTenantRolesURL(endpoint, version, tenantID string) (string, error) {
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

	// Add pagination parameters if specified
	if listTenantRolesStartingAfter != "" {
		q.Set("starting_after", listTenantRolesStartingAfter)
	}
	if listTenantRolesEndingBefore != "" {
		q.Set("ending_before", listTenantRolesEndingBefore)
	}
	if listTenantRolesLimit > 0 {
		q.Set("limit", strconv.Itoa(listTenantRolesLimit))
	}

	// Add filtering parameters if specified
	if listTenantRolesName != "" {
		q.Set("name", listTenantRolesName)
	}
	if listTenantRolesCustom != "" {
		q.Set("custom", listTenantRolesCustom)
	}
	if listTenantRolesAssignableByMe != "" {
		q.Set("assignable_by_me", listTenantRolesAssignableByMe)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListTenantRolesResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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