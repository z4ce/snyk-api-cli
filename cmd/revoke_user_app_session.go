package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RevokeUserAppSessionCmd represents the revoke-user-app-session command
var RevokeUserAppSessionCmd = &cobra.Command{
	Use:   "revoke-user-app-session [app_id] [session_id]",
	Short: "Revoke the Snyk App session of an active user",
	Long: `Revoke the Snyk App session of an active user from the Snyk API.

This command revokes a specific active OAuth session for a Snyk App using both
the app identifier and session identifier. Both app_id and session_id parameters
are required and must be valid UUIDs.

Examples:
  snyk-api-cli revoke-user-app-session 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli revoke-user-app-session --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli revoke-user-app-session --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runRevokeUserAppSession,
}

var (
	revokeUserAppSessionVerbose     bool
	revokeUserAppSessionSilent      bool
	revokeUserAppSessionIncludeResp bool
	revokeUserAppSessionUserAgent   string
)

func init() {
	// Add standard flags like curl command
	RevokeUserAppSessionCmd.Flags().BoolVarP(&revokeUserAppSessionVerbose, "verbose", "v", false, "Make the operation more talkative")
	RevokeUserAppSessionCmd.Flags().BoolVarP(&revokeUserAppSessionSilent, "silent", "s", false, "Silent mode")
	RevokeUserAppSessionCmd.Flags().BoolVarP(&revokeUserAppSessionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	RevokeUserAppSessionCmd.Flags().StringVarP(&revokeUserAppSessionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runRevokeUserAppSession(cmd *cobra.Command, args []string) error {
	appID := args[0]
	sessionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the app_id and session_id path parameters
	fullURL, err := buildRevokeUserAppSessionURL(endpoint, appID, sessionID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     revokeUserAppSessionVerbose,
		Silent:      revokeUserAppSessionSilent,
		IncludeResp: revokeUserAppSessionIncludeResp,
		UserAgent:   revokeUserAppSessionUserAgent,
	})
}

func buildRevokeUserAppSessionURL(endpoint, appID, sessionID, version string) (string, error) {
	// Validate the app_id parameter
	if strings.TrimSpace(appID) == "" {
		return "", fmt.Errorf("app_id cannot be empty")
	}

	// Validate the session_id parameter
	if strings.TrimSpace(sessionID) == "" {
		return "", fmt.Errorf("session_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/self/apps/%s/sessions/%s", endpoint, appID, sessionID)

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
