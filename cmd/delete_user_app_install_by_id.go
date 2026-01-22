package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteUserAppInstallByIdCmd represents the delete-user-app-install-by-id command
var DeleteUserAppInstallByIdCmd = &cobra.Command{
	Use:   "delete-user-app-install-by-id [install_id]",
	Short: "Revoke a Snyk App by install ID",
	Long: `Revoke a Snyk App by install ID from the Snyk API.

This command revokes a specific Snyk App installation using its unique install identifier.
The install_id parameter is required and must be a valid UUID.

Examples:
  snyk-api-cli delete-user-app-install-by-id 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-user-app-install-by-id --verbose 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-user-app-install-by-id --include 12345678-1234-5678-9012-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runDeleteUserAppInstallById,
}

var (
	deleteUserAppInstallByIdVerbose     bool
	deleteUserAppInstallByIdSilent      bool
	deleteUserAppInstallByIdIncludeResp bool
	deleteUserAppInstallByIdUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteUserAppInstallByIdCmd.Flags().BoolVarP(&deleteUserAppInstallByIdVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteUserAppInstallByIdCmd.Flags().BoolVarP(&deleteUserAppInstallByIdSilent, "silent", "s", false, "Silent mode")
	DeleteUserAppInstallByIdCmd.Flags().BoolVarP(&deleteUserAppInstallByIdIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteUserAppInstallByIdCmd.Flags().StringVarP(&deleteUserAppInstallByIdUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteUserAppInstallById(cmd *cobra.Command, args []string) error {
	installID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the install_id path parameter
	fullURL, err := buildDeleteUserAppInstallByIdURL(endpoint, installID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteUserAppInstallByIdVerbose,
		Silent:      deleteUserAppInstallByIdSilent,
		IncludeResp: deleteUserAppInstallByIdIncludeResp,
		UserAgent:   deleteUserAppInstallByIdUserAgent,
	})
}

func buildDeleteUserAppInstallByIdURL(endpoint, installID, version string) (string, error) {
	// Validate the install_id parameter
	if strings.TrimSpace(installID) == "" {
		return "", fmt.Errorf("install_id cannot be empty")
	}

	// Build base URL with the path parameter
	baseURL := fmt.Sprintf("https://%s/rest/self/apps/installs/%s", endpoint, installID)

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
