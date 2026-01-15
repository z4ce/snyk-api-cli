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

// ListOrgInvitationCmd represents the list-org-invitation command
var ListOrgInvitationCmd = &cobra.Command{
	Use:   "list-org-invitation [org_id]",
	Short: "List pending user invitations to an organization",
	Long: `List pending user invitations to an organization from the Snyk API.

This command retrieves a list of pending user invitations for a specific organization.
The organization ID must be provided as a required argument. The results can be
paginated using various query parameters.

Examples:
  snyk-api-cli list-org-invitation 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-org-invitation 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-org-invitation 12345678-1234-1234-1234-123456789012 --starting-after "v1.eyJpZCI6IjEwMDAifQo="
  snyk-api-cli list-org-invitation 12345678-1234-1234-1234-123456789012 --ending-before "v1.eyJpZCI6IjExMDAifQo="
  snyk-api-cli list-org-invitation 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListOrgInvitation,
}

var (
	listOrgInvitationLimit         int
	listOrgInvitationStartingAfter string
	listOrgInvitationEndingBefore  string
	listOrgInvitationVerbose       bool
	listOrgInvitationSilent        bool
	listOrgInvitationIncludeResp   bool
	listOrgInvitationUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListOrgInvitationCmd.Flags().IntVar(&listOrgInvitationLimit, "limit", 0, "Number of results to return per page")
	ListOrgInvitationCmd.Flags().StringVar(&listOrgInvitationStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListOrgInvitationCmd.Flags().StringVar(&listOrgInvitationEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")

	// Add standard flags like other commands
	ListOrgInvitationCmd.Flags().BoolVarP(&listOrgInvitationVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgInvitationCmd.Flags().BoolVarP(&listOrgInvitationSilent, "silent", "s", false, "Silent mode")
	ListOrgInvitationCmd.Flags().BoolVarP(&listOrgInvitationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgInvitationCmd.Flags().StringVarP(&listOrgInvitationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgInvitation(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgInvitationURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listOrgInvitationVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listOrgInvitationVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listOrgInvitationUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListOrgInvitationResponse(resp, listOrgInvitationIncludeResp, listOrgInvitationVerbose, listOrgInvitationSilent)
}

func buildListOrgInvitationURL(endpoint, version, orgID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/invites", endpoint, orgID)

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
	if listOrgInvitationLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listOrgInvitationLimit))
	}
	if listOrgInvitationStartingAfter != "" {
		q.Set("starting_after", listOrgInvitationStartingAfter)
	}
	if listOrgInvitationEndingBefore != "" {
		q.Set("ending_before", listOrgInvitationEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListOrgInvitationResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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