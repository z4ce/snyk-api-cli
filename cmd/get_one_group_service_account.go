package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetOneGroupServiceAccountCmd represents the get-one-group-service-account command
var GetOneGroupServiceAccountCmd = &cobra.Command{
	Use:   "get-one-group-service-account <group_id> <serviceaccount_id>",
	Short: "Get details of a specific group service account",
	Long: `Get details of a specific group service account from the Snyk API.

This command retrieves detailed information about a service account within a specific group,
including its name, auth_type, role_id, and creation date.

Examples:
  snyk-api-cli get-one-group-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-one-group-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-one-group-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetOneGroupServiceAccount,
}

var (
	getOneGroupServiceAccountVerbose     bool
	getOneGroupServiceAccountSilent      bool
	getOneGroupServiceAccountIncludeResp bool
	getOneGroupServiceAccountUserAgent   string
)

func init() {
	// Add standard flags like curl command
	GetOneGroupServiceAccountCmd.Flags().BoolVarP(&getOneGroupServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOneGroupServiceAccountCmd.Flags().BoolVarP(&getOneGroupServiceAccountSilent, "silent", "s", false, "Silent mode")
	GetOneGroupServiceAccountCmd.Flags().BoolVarP(&getOneGroupServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOneGroupServiceAccountCmd.Flags().StringVarP(&getOneGroupServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOneGroupServiceAccount(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	serviceAccountID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with path parameters
	fullURL, err := buildGetOneGroupServiceAccountURL(endpoint, version, groupID, serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getOneGroupServiceAccountVerbose,
		Silent:      getOneGroupServiceAccountSilent,
		IncludeResp: getOneGroupServiceAccountIncludeResp,
		UserAgent:   getOneGroupServiceAccountUserAgent,
	})
}

func buildGetOneGroupServiceAccountURL(endpoint, version, groupID, serviceAccountID string) (string, error) {
	// Build base URL with path parameters
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
