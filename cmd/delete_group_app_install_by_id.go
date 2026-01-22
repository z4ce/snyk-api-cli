package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteGroupAppInstallByIdCmd represents the delete-group-app-install-by-id command
var DeleteGroupAppInstallByIdCmd = &cobra.Command{
	Use:   "delete-group-app-install-by-id [group_id] [install_id]",
	Short: "Revoke app authorization for a Snyk group with install ID",
	Long: `Revoke app authorization for a Snyk group with install ID.

This command deletes a specific app install using the group ID and install ID parameters.
Both group_id and install_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-group-app-install-by-id 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-app-install-by-id --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-app-install-by-id --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteGroupAppInstallById,
}

var (
	deleteGroupAppInstallByIdVerbose     bool
	deleteGroupAppInstallByIdSilent      bool
	deleteGroupAppInstallByIdIncludeResp bool
	deleteGroupAppInstallByIdUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteGroupAppInstallByIdCmd.Flags().BoolVarP(&deleteGroupAppInstallByIdVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteGroupAppInstallByIdCmd.Flags().BoolVarP(&deleteGroupAppInstallByIdSilent, "silent", "s", false, "Silent mode")
	DeleteGroupAppInstallByIdCmd.Flags().BoolVarP(&deleteGroupAppInstallByIdIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteGroupAppInstallByIdCmd.Flags().StringVarP(&deleteGroupAppInstallByIdUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteGroupAppInstallById(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	installID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id and install_id path parameters
	fullURL, err := buildDeleteGroupAppInstallByIdURL(endpoint, groupID, installID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteGroupAppInstallByIdVerbose,
		Silent:      deleteGroupAppInstallByIdSilent,
		IncludeResp: deleteGroupAppInstallByIdIncludeResp,
		UserAgent:   deleteGroupAppInstallByIdUserAgent,
	})
}

func buildDeleteGroupAppInstallByIdURL(endpoint, groupID, installID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Validate the install_id parameter
	if strings.TrimSpace(installID) == "" {
		return "", fmt.Errorf("install_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/apps/installs/%s", endpoint, groupID, installID)

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
