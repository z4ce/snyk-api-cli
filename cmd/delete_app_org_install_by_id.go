package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteAppOrgInstallByIdCmd represents the delete-app-org-install-by-id command
var DeleteAppOrgInstallByIdCmd = &cobra.Command{
	Use:   "delete-app-org-install-by-id [org_id] [install_id]",
	Short: "Revoke app authorization for a Snyk organization with install ID",
	Long: `Revoke app authorization for a Snyk organization with install ID.

This command deletes a specific app install using the org ID and install ID parameters.
Both org_id and install_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-app-org-install-by-id 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-app-org-install-by-id --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-app-org-install-by-id --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteAppOrgInstallById,
}

var (
	deleteAppOrgInstallByIdVerbose     bool
	deleteAppOrgInstallByIdSilent      bool
	deleteAppOrgInstallByIdIncludeResp bool
	deleteAppOrgInstallByIdUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteAppOrgInstallByIdCmd.Flags().BoolVarP(&deleteAppOrgInstallByIdVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteAppOrgInstallByIdCmd.Flags().BoolVarP(&deleteAppOrgInstallByIdSilent, "silent", "s", false, "Silent mode")
	DeleteAppOrgInstallByIdCmd.Flags().BoolVarP(&deleteAppOrgInstallByIdIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteAppOrgInstallByIdCmd.Flags().StringVarP(&deleteAppOrgInstallByIdUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteAppOrgInstallById(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	installID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and install_id path parameters
	fullURL, err := buildDeleteAppOrgInstallByIdURL(endpoint, orgID, installID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteAppOrgInstallByIdVerbose,
		Silent:      deleteAppOrgInstallByIdSilent,
		IncludeResp: deleteAppOrgInstallByIdIncludeResp,
		UserAgent:   deleteAppOrgInstallByIdUserAgent,
	})
}

func buildDeleteAppOrgInstallByIdURL(endpoint, orgID, installID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the install_id parameter
	if strings.TrimSpace(installID) == "" {
		return "", fmt.Errorf("install_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/installs/%s", endpoint, orgID, installID)

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
