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

// DeleteOrgMembershipCmd represents the delete-org-membership command
var DeleteOrgMembershipCmd = &cobra.Command{
	Use:   "delete-org-membership [org_id] [membership_id]",
	Short: "Remove user's organization membership from Snyk",
	Long: `Remove user's organization membership from the Snyk API.

This command deletes a specific organization membership using its unique identifier within an organization.
Both org_id and membership_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-org-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987
  snyk-api-cli delete-org-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --verbose
  snyk-api-cli delete-org-membership 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOrgMembership,
}

var (
	deleteOrgMembershipVerbose     bool
	deleteOrgMembershipSilent      bool
	deleteOrgMembershipIncludeResp bool
	deleteOrgMembershipUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteOrgMembershipCmd.Flags().BoolVarP(&deleteOrgMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgMembershipCmd.Flags().BoolVarP(&deleteOrgMembershipSilent, "silent", "s", false, "Silent mode")
	DeleteOrgMembershipCmd.Flags().BoolVarP(&deleteOrgMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgMembershipCmd.Flags().StringVarP(&deleteOrgMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgMembership(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	membershipID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and membership_id path parameters
	fullURL, err := buildDeleteOrgMembershipURL(endpoint, orgID, membershipID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteOrgMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteOrgMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteOrgMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteOrgMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteOrgMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteOrgMembershipUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteOrgMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteOrgMembershipResponse(resp, deleteOrgMembershipIncludeResp, deleteOrgMembershipVerbose, deleteOrgMembershipSilent)
}

func buildDeleteOrgMembershipURL(endpoint, orgID, membershipID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the membership_id parameter
	if strings.TrimSpace(membershipID) == "" {
		return "", fmt.Errorf("membership_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/memberships/%s", endpoint, orgID, membershipID)

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

func handleDeleteOrgMembershipResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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