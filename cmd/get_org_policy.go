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

// GetOrgPolicyCmd represents the get-org-policy command
var GetOrgPolicyCmd = &cobra.Command{
	Use:   "get-org-policy [org_id] [policy_id]",
	Short: "Get an organization-level policy by ID from Snyk",
	Long: `Get an organization-level policy by ID from the Snyk API.

This command retrieves detailed information about a specific organization-level policy by its ID within an organization.
Both the organization ID and policy ID must be provided as required arguments.

Note: Organization-level Policy APIs are only available for Code Consistent Ignores.

Required permissions: View Ignores (org.project.ignore.read)

Examples:
  snyk-api-cli get-org-policy 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987
  snyk-api-cli get-org-policy 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --verbose
  snyk-api-cli get-org-policy 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetOrgPolicy,
}

var (
	getOrgPolicyVerbose     bool
	getOrgPolicySilent      bool
	getOrgPolicyIncludeResp bool
	getOrgPolicyUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetOrgPolicyCmd.Flags().BoolVarP(&getOrgPolicyVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgPolicyCmd.Flags().BoolVarP(&getOrgPolicySilent, "silent", "s", false, "Silent mode")
	GetOrgPolicyCmd.Flags().BoolVarP(&getOrgPolicyIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgPolicyCmd.Flags().StringVarP(&getOrgPolicyUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOrgPolicy(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	policyID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetOrgPolicyURL(endpoint, version, orgID, policyID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getOrgPolicyVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getOrgPolicyVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getOrgPolicyUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetOrgPolicyResponse(resp, getOrgPolicyIncludeResp, getOrgPolicyVerbose, getOrgPolicySilent)
}

func buildGetOrgPolicyURL(endpoint, version, orgID, policyID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(policyID) == "" {
		return "", fmt.Errorf("policy_id cannot be empty")
	}

	// Build base URL with organization ID and policy ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/policies/%s", endpoint, orgID, policyID)

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

func handleGetOrgPolicyResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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