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

// DeleteOrgInvitationCmd represents the delete-org-invitation command
var DeleteOrgInvitationCmd = &cobra.Command{
	Use:   "delete-org-invitation [org_id] [invite_id]",
	Short: "Cancel a pending user invitation to an organization",
	Long: `Cancel a pending user invitation to an organization from the Snyk API.

This command cancels a specific pending invitation using its unique identifier within an organization.
Both org_id and invite_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-org-invitation 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-org-invitation --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-org-invitation --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOrgInvitation,
}

var (
	deleteOrgInvitationVerbose     bool
	deleteOrgInvitationSilent      bool
	deleteOrgInvitationIncludeResp bool
	deleteOrgInvitationUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteOrgInvitationCmd.Flags().BoolVarP(&deleteOrgInvitationVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgInvitationCmd.Flags().BoolVarP(&deleteOrgInvitationSilent, "silent", "s", false, "Silent mode")
	DeleteOrgInvitationCmd.Flags().BoolVarP(&deleteOrgInvitationIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgInvitationCmd.Flags().StringVarP(&deleteOrgInvitationUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgInvitation(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	inviteID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and invite_id path parameters
	fullURL, err := buildDeleteOrgInvitationURL(endpoint, orgID, inviteID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteOrgInvitationVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteOrgInvitationVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteOrgInvitationUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteOrgInvitationVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteOrgInvitationResponse(resp, deleteOrgInvitationIncludeResp, deleteOrgInvitationVerbose, deleteOrgInvitationSilent)
}

func buildDeleteOrgInvitationURL(endpoint, orgID, inviteID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the invite_id parameter
	if strings.TrimSpace(inviteID) == "" {
		return "", fmt.Errorf("invite_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/invites/%s", endpoint, orgID, inviteID)

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

func handleDeleteOrgInvitationResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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