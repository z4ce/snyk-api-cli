package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteOneGroupServiceAccountCmd represents the delete-one-group-service-account command
var DeleteOneGroupServiceAccountCmd = &cobra.Command{
	Use:   "delete-one-group-service-account [group_id] [serviceaccount_id]",
	Short: "Delete a group service account from Snyk",
	Long: `Delete a group service account from the Snyk API.

This command permanently deletes a specific group-level service account using the group ID and service account ID.
Both group_id and serviceaccount_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-one-group-service-account 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-one-group-service-account --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-one-group-service-account --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOneGroupServiceAccount,
}

var (
	deleteOneGroupServiceAccountVerbose     bool
	deleteOneGroupServiceAccountSilent      bool
	deleteOneGroupServiceAccountIncludeResp bool
	deleteOneGroupServiceAccountUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteOneGroupServiceAccountCmd.Flags().BoolVarP(&deleteOneGroupServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOneGroupServiceAccountCmd.Flags().BoolVarP(&deleteOneGroupServiceAccountSilent, "silent", "s", false, "Silent mode")
	DeleteOneGroupServiceAccountCmd.Flags().BoolVarP(&deleteOneGroupServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOneGroupServiceAccountCmd.Flags().StringVarP(&deleteOneGroupServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOneGroupServiceAccount(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	serviceAccountID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id and serviceaccount_id path parameters
	fullURL, err := buildDeleteOneGroupServiceAccountURL(endpoint, groupID, serviceAccountID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteOneGroupServiceAccountVerbose,
		Silent:      deleteOneGroupServiceAccountSilent,
		IncludeResp: deleteOneGroupServiceAccountIncludeResp,
		UserAgent:   deleteOneGroupServiceAccountUserAgent,
	})
}

func buildDeleteOneGroupServiceAccountURL(endpoint, groupID, serviceAccountID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Validate the serviceaccount_id parameter
	if strings.TrimSpace(serviceAccountID) == "" {
		return "", fmt.Errorf("serviceaccount_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/service_accounts/%s", endpoint, groupID, serviceAccountID)

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
