package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RevokeUserInstalledAppCmd represents the revoke-user-installed-app command
var RevokeUserInstalledAppCmd = &cobra.Command{
	Use:   "revoke-user-installed-app [app_id]",
	Short: "Revoke a Snyk App by app ID",
	Long: `Revoke a Snyk App by app ID from the Snyk API.

This command revokes access to a specific Snyk App using its unique app identifier.
The app_id parameter is required and must be a valid UUID.

Examples:
  snyk-api-cli revoke-user-installed-app 12345678-1234-5678-9012-123456789012
  snyk-api-cli revoke-user-installed-app --verbose 12345678-1234-5678-9012-123456789012
  snyk-api-cli revoke-user-installed-app --include 12345678-1234-5678-9012-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runRevokeUserInstalledApp,
}

var (
	revokeUserInstalledAppVerbose     bool
	revokeUserInstalledAppSilent      bool
	revokeUserInstalledAppIncludeResp bool
	revokeUserInstalledAppUserAgent   string
)

func init() {
	// Add standard flags like curl command
	RevokeUserInstalledAppCmd.Flags().BoolVarP(&revokeUserInstalledAppVerbose, "verbose", "v", false, "Make the operation more talkative")
	RevokeUserInstalledAppCmd.Flags().BoolVarP(&revokeUserInstalledAppSilent, "silent", "s", false, "Silent mode")
	RevokeUserInstalledAppCmd.Flags().BoolVarP(&revokeUserInstalledAppIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	RevokeUserInstalledAppCmd.Flags().StringVarP(&revokeUserInstalledAppUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runRevokeUserInstalledApp(cmd *cobra.Command, args []string) error {
	appID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the app_id path parameter
	fullURL, err := buildRevokeUserInstalledAppURL(endpoint, appID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     revokeUserInstalledAppVerbose,
		Silent:      revokeUserInstalledAppSilent,
		IncludeResp: revokeUserInstalledAppIncludeResp,
		UserAgent:   revokeUserInstalledAppUserAgent,
	})
}

func buildRevokeUserInstalledAppURL(endpoint, appID, version string) (string, error) {
	// Validate the app_id parameter
	if strings.TrimSpace(appID) == "" {
		return "", fmt.Errorf("app_id cannot be empty")
	}

	// Build base URL with the path parameter
	baseURL := fmt.Sprintf("https://%s/rest/self/apps/%s", endpoint, appID)

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
