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

// DeleteOrgPolicyCmd represents the delete-org-policy command
var DeleteOrgPolicyCmd = &cobra.Command{
	Use:   "delete-org-policy [org_id] [policy_id]",
	Short: "Delete an organization-level policy by ID from Snyk",
	Long: `Delete an organization-level policy by ID from the Snyk API.

This command deletes a specific organization-level policy using its unique identifier within an organization.
Both org_id and policy_id parameters are required and must be valid UUIDs.

Note: Organization-level Policy APIs are only available for Code Consistent Ignores.

Required permissions: Remove Ignores (org.project.ignore.delete)

Examples:
  snyk-api-cli delete-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli delete-org-policy 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOrgPolicy,
}

var (
	deleteOrgPolicyVerbose     bool
	deleteOrgPolicySilent      bool
	deleteOrgPolicyIncludeResp bool
	deleteOrgPolicyUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteOrgPolicyCmd.Flags().BoolVarP(&deleteOrgPolicyVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgPolicyCmd.Flags().BoolVarP(&deleteOrgPolicySilent, "silent", "s", false, "Silent mode")
	DeleteOrgPolicyCmd.Flags().BoolVarP(&deleteOrgPolicyIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgPolicyCmd.Flags().StringVarP(&deleteOrgPolicyUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgPolicy(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	policyID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and policy_id path parameters
	fullURL, err := buildDeleteOrgPolicyURL(endpoint, orgID, policyID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteOrgPolicyVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteOrgPolicyVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteOrgPolicyUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteOrgPolicyVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteOrgPolicyResponse(resp, deleteOrgPolicyIncludeResp, deleteOrgPolicyVerbose, deleteOrgPolicySilent)
}

func buildDeleteOrgPolicyURL(endpoint, orgID, policyID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the policy_id parameter
	if strings.TrimSpace(policyID) == "" {
		return "", fmt.Errorf("policy_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/policies/%s", endpoint, orgID, policyID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add required version query parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func handleDeleteOrgPolicyResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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