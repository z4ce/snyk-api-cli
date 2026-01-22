package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetOneOrgServiceAccountCmd represents the get-one-org-service-account command
var GetOneOrgServiceAccountCmd = &cobra.Command{
	Use:   "get-one-org-service-account [org_id] [serviceaccount_id]",
	Short: "Get an organization service account",
	Long: `Get an organization service account by ID from the Snyk API.

This command retrieves detailed information about a specific service account by its ID within an organization.
Both the organization ID and service account ID must be provided as required arguments.

Required permissions: View service accounts (org.service_account.read)

Examples:
  snyk-api-cli get-one-org-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-one-org-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli get-one-org-service-account 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetOneOrgServiceAccount,
}

var (
	getOneOrgServiceAccountVerbose     bool
	getOneOrgServiceAccountSilent      bool
	getOneOrgServiceAccountIncludeResp bool
	getOneOrgServiceAccountUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetOneOrgServiceAccountCmd.Flags().BoolVarP(&getOneOrgServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOneOrgServiceAccountCmd.Flags().BoolVarP(&getOneOrgServiceAccountSilent, "silent", "s", false, "Silent mode")
	GetOneOrgServiceAccountCmd.Flags().BoolVarP(&getOneOrgServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOneOrgServiceAccountCmd.Flags().StringVarP(&getOneOrgServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOneOrgServiceAccount(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	serviceAccountID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetOneOrgServiceAccountURL(endpoint, version, orgID, serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getOneOrgServiceAccountVerbose,
		Silent:      getOneOrgServiceAccountSilent,
		IncludeResp: getOneOrgServiceAccountIncludeResp,
		UserAgent:   getOneOrgServiceAccountUserAgent,
	})
}

func buildGetOneOrgServiceAccountURL(endpoint, version, orgID, serviceAccountID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(serviceAccountID) == "" {
		return "", fmt.Errorf("serviceaccount_id cannot be empty")
	}

	// Build base URL with organization ID and service account ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/service_accounts/%s", endpoint, orgID, serviceAccountID)

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
