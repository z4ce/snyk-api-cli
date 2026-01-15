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

// DeleteUserCmd represents the delete-user command
var DeleteUserCmd = &cobra.Command{
	Use:   "delete-user [group_id] [sso_id] [user_id]",
	Short: "Delete a user from an SSO connection in Snyk",
	Long: `Delete a user from an SSO connection in the Snyk API.

This command deletes a specific user from an SSO connection using the group ID, SSO ID, and user ID.
All three parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-user 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 11111111-2222-3333-4444-555555555555
  snyk-api-cli delete-user --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 11111111-2222-3333-4444-555555555555
  snyk-api-cli delete-user --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 11111111-2222-3333-4444-555555555555`,
	Args: cobra.ExactArgs(3),
	RunE: runDeleteUser,
}

var (
	deleteUserVerbose     bool
	deleteUserSilent      bool
	deleteUserIncludeResp bool
	deleteUserUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteUserCmd.Flags().BoolVarP(&deleteUserVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteUserCmd.Flags().BoolVarP(&deleteUserSilent, "silent", "s", false, "Silent mode")
	DeleteUserCmd.Flags().BoolVarP(&deleteUserIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteUserCmd.Flags().StringVarP(&deleteUserUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteUser(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	ssoID := args[1]
	userID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id, sso_id, and user_id path parameters
	fullURL, err := buildDeleteUserURL(endpoint, groupID, ssoID, userID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteUserVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteUserVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteUserVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteUserVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteUserVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteUserUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteUserVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteUserResponse(resp, deleteUserIncludeResp, deleteUserVerbose, deleteUserSilent)
}

func buildDeleteUserURL(endpoint, groupID, ssoID, userID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Validate the sso_id parameter
	if strings.TrimSpace(ssoID) == "" {
		return "", fmt.Errorf("sso_id cannot be empty")
	}

	// Validate the user_id parameter
	if strings.TrimSpace(userID) == "" {
		return "", fmt.Errorf("user_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/sso_connections/%s/users/%s", endpoint, groupID, ssoID, userID)

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

func handleDeleteUserResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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