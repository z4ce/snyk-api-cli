package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetAPIVersionCmd represents the get-api-version command
var GetAPIVersionCmd = &cobra.Command{
	Use:   "get-api-version [version]",
	Short: "Get OpenAPI specification effective at version",
	Long: `Get OpenAPI specification effective at version from the Snyk API.

This command retrieves the OpenAPI specification for a specific version
of the Snyk API. The version parameter is required and specifies which
version of the API specification to retrieve.

Examples:
  snyk-api-cli get-api-version 2024-10-15
  snyk-api-cli get-api-version 2024-10-15 --verbose
  snyk-api-cli get-api-version 2024-10-15 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetAPIVersion,
}

var (
	getAPIVersionVerbose     bool
	getAPIVersionSilent      bool
	getAPIVersionIncludeResp bool
	getAPIVersionUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetAPIVersionCmd.Flags().BoolVarP(&getAPIVersionVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAPIVersionCmd.Flags().BoolVarP(&getAPIVersionSilent, "silent", "s", false, "Silent mode")
	GetAPIVersionCmd.Flags().BoolVarP(&getAPIVersionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAPIVersionCmd.Flags().StringVarP(&getAPIVersionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAPIVersion(cmd *cobra.Command, args []string) error {
	version := args[0]
	endpoint := viper.GetString("endpoint")
	defaultVersion := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetAPIVersionURL(endpoint, version, defaultVersion)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getAPIVersionVerbose,
		Silent:      getAPIVersionSilent,
		IncludeResp: getAPIVersionIncludeResp,
		UserAgent:   getAPIVersionUserAgent,
	})
}

func buildGetAPIVersionURL(endpoint, version, defaultVersion string) (string, error) {
	// Build base URL for the /openapi/{version} endpoint
	baseURL := fmt.Sprintf("https://%s/openapi/%s", endpoint, version)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required for REST endpoints
	q.Set("version", defaultVersion)

	u.RawQuery = q.Encode()
	return u.String(), nil
}
