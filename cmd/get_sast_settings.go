package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetSastSettingsCmd represents the get-sast-settings command
var GetSastSettingsCmd = &cobra.Command{
	Use:   "get-sast-settings [org_id]",
	Short: "Get SAST settings for an organization",
	Long: `Get SAST settings for an organization from the Snyk API.

This command retrieves the SAST (Static Application Security Testing) settings for a specific organization by its ID.
The organization ID must be provided as a required argument.

Required permissions: View Organization (org.read)

Examples:
  snyk-api-cli get-sast-settings 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-sast-settings 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-sast-settings 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetSastSettings,
}

var (
	getSastSettingsVerbose     bool
	getSastSettingsSilent      bool
	getSastSettingsIncludeResp bool
	getSastSettingsUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetSastSettingsCmd.Flags().BoolVarP(&getSastSettingsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetSastSettingsCmd.Flags().BoolVarP(&getSastSettingsSilent, "silent", "s", false, "Silent mode")
	GetSastSettingsCmd.Flags().BoolVarP(&getSastSettingsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetSastSettingsCmd.Flags().StringVarP(&getSastSettingsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetSastSettings(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetSastSettingsURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getSastSettingsVerbose,
		Silent:      getSastSettingsSilent,
		IncludeResp: getSastSettingsIncludeResp,
		UserAgent:   getSastSettingsUserAgent,
	})
}

func buildGetSastSettingsURL(endpoint, version, orgID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/settings/sast", endpoint, orgID)

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
