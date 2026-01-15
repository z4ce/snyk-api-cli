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

// DeleteGroupMembershipCmd represents the delete-group-membership command
var DeleteGroupMembershipCmd = &cobra.Command{
	Use:   "delete-group-membership [group_id] [membership_id]",
	Short: "Delete a group membership from Snyk",
	Long: `Delete a group membership from the Snyk API.

This command deletes a specific group membership using the group ID and membership ID.
Both group_id and membership_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-group-membership 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-membership 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --cascade
  snyk-api-cli delete-group-membership --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-membership --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteGroupMembership,
}

var (
	deleteGroupMembershipCascade     bool
	deleteGroupMembershipVerbose     bool
	deleteGroupMembershipSilent      bool
	deleteGroupMembershipIncludeResp bool
	deleteGroupMembershipUserAgent   string
)

func init() {
	// Add cascade flag for the optional query parameter
	DeleteGroupMembershipCmd.Flags().BoolVar(&deleteGroupMembershipCascade, "cascade", false, "Indicates whether to delete child org memberships")

	// Add standard flags like curl command
	DeleteGroupMembershipCmd.Flags().BoolVarP(&deleteGroupMembershipVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteGroupMembershipCmd.Flags().BoolVarP(&deleteGroupMembershipSilent, "silent", "s", false, "Silent mode")
	DeleteGroupMembershipCmd.Flags().BoolVarP(&deleteGroupMembershipIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteGroupMembershipCmd.Flags().StringVarP(&deleteGroupMembershipUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteGroupMembership(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	membershipID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id and membership_id path parameters
	fullURL, err := buildDeleteGroupMembershipURL(endpoint, groupID, membershipID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteGroupMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteGroupMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteGroupMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteGroupMembershipVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteGroupMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteGroupMembershipUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteGroupMembershipVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleDeleteGroupMembershipResponse(resp, deleteGroupMembershipIncludeResp, deleteGroupMembershipVerbose, deleteGroupMembershipSilent)
}

func buildDeleteGroupMembershipURL(endpoint, groupID, membershipID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Validate the membership_id parameter
	if strings.TrimSpace(membershipID) == "" {
		return "", fmt.Errorf("membership_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/memberships/%s", endpoint, groupID, membershipID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional cascade parameter if provided
	if deleteGroupMembershipCascade {
		q.Set("cascade", "true")
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleDeleteGroupMembershipResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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