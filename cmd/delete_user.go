package cmd

import (
	"fmt"
	"net/url"
	"strings"

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

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteUserVerbose,
		Silent:      deleteUserSilent,
		IncludeResp: deleteUserIncludeResp,
		UserAgent:   deleteUserUserAgent,
	})
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
