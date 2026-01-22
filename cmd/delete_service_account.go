package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteServiceAccountCmd represents the delete-service-account command
var DeleteServiceAccountCmd = &cobra.Command{
	Use:   "delete-service-account [org_id] [serviceaccount_id]",
	Short: "Delete a service account in an organization",
	Long: `Delete a service account by ID from the Snyk API.

This command deletes a specific service account using its unique identifier within an organization.
Both org_id and serviceaccount_id parameters are required and must be valid UUIDs.

Required permissions: Remove service accounts (org.service_account.delete)

Examples:
  snyk-api-cli delete-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli delete-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteServiceAccount,
}

var (
	deleteServiceAccountVerbose     bool
	deleteServiceAccountSilent      bool
	deleteServiceAccountIncludeResp bool
	deleteServiceAccountUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteServiceAccountCmd.Flags().BoolVarP(&deleteServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteServiceAccountCmd.Flags().BoolVarP(&deleteServiceAccountSilent, "silent", "s", false, "Silent mode")
	DeleteServiceAccountCmd.Flags().BoolVarP(&deleteServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteServiceAccountCmd.Flags().StringVarP(&deleteServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteServiceAccount(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	serviceAccountID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and serviceaccount_id path parameters
	fullURL, err := buildDeleteServiceAccountURL(endpoint, orgID, serviceAccountID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteServiceAccountVerbose,
		Silent:      deleteServiceAccountSilent,
		IncludeResp: deleteServiceAccountIncludeResp,
		UserAgent:   deleteServiceAccountUserAgent,
	})
}

func buildDeleteServiceAccountURL(endpoint, orgID, serviceAccountID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the serviceaccount_id parameter
	if strings.TrimSpace(serviceAccountID) == "" {
		return "", fmt.Errorf("serviceaccount_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/service_accounts/%s", endpoint, orgID, serviceAccountID)

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
