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

// GetOrgPolicyEventsCmd represents the get-org-policy-events command
var GetOrgPolicyEventsCmd = &cobra.Command{
	Use:   "get-org-policy-events [org_id] [policy_id]",
	Short: "List organization-level policy events from Snyk",
	Long: `List organization-level policy events from the Snyk API for a specific policy.

This command retrieves a list of events for an organization-level policy that the authenticated user can access
within the specified organization. The results can be paginated using various query parameters.

Note: Organization-level Policy APIs are only available for Code Consistent Ignores.

Required permissions: View Ignores (org.project.ignore.read)

Examples:
  snyk-api-cli get-org-policy-events 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987
  snyk-api-cli get-org-policy-events 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --limit 10
  snyk-api-cli get-org-policy-events 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --starting-after "v1.eyJpZCI6IjEwMDAifQo="
  snyk-api-cli get-org-policy-events 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --ending-before "v1.eyJpZCI6IjExMDAifQo="
  snyk-api-cli get-org-policy-events 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runGetOrgPolicyEvents,
}

var (
	getOrgPolicyEventsLimit         int
	getOrgPolicyEventsStartingAfter string
	getOrgPolicyEventsEndingBefore  string
	getOrgPolicyEventsVerbose       bool
	getOrgPolicyEventsSilent        bool
	getOrgPolicyEventsIncludeResp   bool
	getOrgPolicyEventsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetOrgPolicyEventsCmd.Flags().IntVar(&getOrgPolicyEventsLimit, "limit", 0, "Number of results to return per page")
	GetOrgPolicyEventsCmd.Flags().StringVar(&getOrgPolicyEventsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetOrgPolicyEventsCmd.Flags().StringVar(&getOrgPolicyEventsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")

	// Add standard flags like other commands
	GetOrgPolicyEventsCmd.Flags().BoolVarP(&getOrgPolicyEventsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgPolicyEventsCmd.Flags().BoolVarP(&getOrgPolicyEventsSilent, "silent", "s", false, "Silent mode")
	GetOrgPolicyEventsCmd.Flags().BoolVarP(&getOrgPolicyEventsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgPolicyEventsCmd.Flags().StringVarP(&getOrgPolicyEventsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOrgPolicyEvents(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	policyID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetOrgPolicyEventsURL(endpoint, version, orgID, policyID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getOrgPolicyEventsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getOrgPolicyEventsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getOrgPolicyEventsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getOrgPolicyEventsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getOrgPolicyEventsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getOrgPolicyEventsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getOrgPolicyEventsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetOrgPolicyEventsResponse(resp, getOrgPolicyEventsIncludeResp, getOrgPolicyEventsVerbose, getOrgPolicyEventsSilent)
}

func buildGetOrgPolicyEventsURL(endpoint, version, orgID, policyID string, cmd *cobra.Command) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(policyID) == "" {
		return "", fmt.Errorf("policy_id cannot be empty")
	}

	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/policies/%s/events", endpoint, orgID, policyID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional parameters if provided
	if getOrgPolicyEventsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getOrgPolicyEventsLimit))
	}
	if getOrgPolicyEventsStartingAfter != "" {
		q.Set("starting_after", getOrgPolicyEventsStartingAfter)
	}
	if getOrgPolicyEventsEndingBefore != "" {
		q.Set("ending_before", getOrgPolicyEventsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetOrgPolicyEventsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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