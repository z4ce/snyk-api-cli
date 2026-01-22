package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetSelfCmd represents the get-self command
var GetSelfCmd = &cobra.Command{
	Use:   "get-self",
	Short: "Get my user details from Snyk",
	Long: `Get my user details from the Snyk API.

This command retrieves detailed information about the authenticated user,
including user ID, type (user/service account/app), and other profile details.

Required permissions: Basic authentication (read own profile)

Examples:
  snyk-api-cli get-self
  snyk-api-cli get-self --verbose
  snyk-api-cli get-self --include`,
	Args: cobra.NoArgs,
	RunE: runGetSelf,
}

var (
	getSelfVerbose     bool
	getSelfSilent      bool
	getSelfIncludeResp bool
	getSelfUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetSelfCmd.Flags().BoolVarP(&getSelfVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetSelfCmd.Flags().BoolVarP(&getSelfSilent, "silent", "s", false, "Silent mode")
	GetSelfCmd.Flags().BoolVarP(&getSelfIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetSelfCmd.Flags().StringVarP(&getSelfUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetSelf(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetSelfURL(endpoint, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getSelfVerbose,
		Silent:      getSelfSilent,
		IncludeResp: getSelfIncludeResp,
		UserAgent:   getSelfUserAgent,
	})
}

func buildGetSelfURL(endpoint, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/self", endpoint)

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
