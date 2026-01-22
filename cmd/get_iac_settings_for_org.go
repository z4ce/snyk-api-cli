package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetIacSettingsForOrgCmd represents the get-iac-settings-for-org command
var GetIacSettingsForOrgCmd = &cobra.Command{
	Use:   "get-iac-settings-for-org [org_id]",
	Short: "Get Infrastructure as Code settings for an organization",
	Long: `Get Infrastructure as Code settings for an organization from the Snyk API.

This command retrieves the Infrastructure as Code settings for a specific organization by its ID.
The organization ID must be provided as a required argument.

Required permissions: View Organization (org.read)

Examples:
  snyk-api-cli get-iac-settings-for-org 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-iac-settings-for-org 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-iac-settings-for-org 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetIacSettingsForOrg,
}

var (
	getIacSettingsForOrgVerbose     bool
	getIacSettingsForOrgSilent      bool
	getIacSettingsForOrgIncludeResp bool
	getIacSettingsForOrgUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetIacSettingsForOrgCmd.Flags().BoolVarP(&getIacSettingsForOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetIacSettingsForOrgCmd.Flags().BoolVarP(&getIacSettingsForOrgSilent, "silent", "s", false, "Silent mode")
	GetIacSettingsForOrgCmd.Flags().BoolVarP(&getIacSettingsForOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetIacSettingsForOrgCmd.Flags().StringVarP(&getIacSettingsForOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetIacSettingsForOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetIacSettingsForOrgURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getIacSettingsForOrgVerbose,
		Silent:      getIacSettingsForOrgSilent,
		IncludeResp: getIacSettingsForOrgIncludeResp,
		UserAgent:   getIacSettingsForOrgUserAgent,
	})
}

func buildGetIacSettingsForOrgURL(endpoint, version, orgID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/settings/iac", endpoint, orgID)

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
