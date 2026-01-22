package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListAPIVersionsCmd represents the list-api-versions command
var ListAPIVersionsCmd = &cobra.Command{
	Use:   "list-api-versions",
	Short: "List available versions of OpenAPI specification",
	Long: `List available versions of OpenAPI specification from the Snyk API.

This command retrieves a list of available API versions that can be used
with the Snyk REST API endpoints. The versions are returned as an array
of strings.

Examples:
  snyk-api-cli list-api-versions
  snyk-api-cli list-api-versions --verbose
  snyk-api-cli list-api-versions --include`,
	RunE: runListAPIVersions,
}

var (
	listAPIVersionsVerbose     bool
	listAPIVersionsSilent      bool
	listAPIVersionsIncludeResp bool
	listAPIVersionsUserAgent   string
)

func init() {
	// Add standard flags like other commands
	ListAPIVersionsCmd.Flags().BoolVarP(&listAPIVersionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListAPIVersionsCmd.Flags().BoolVarP(&listAPIVersionsSilent, "silent", "s", false, "Silent mode")
	ListAPIVersionsCmd.Flags().BoolVarP(&listAPIVersionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListAPIVersionsCmd.Flags().StringVarP(&listAPIVersionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListAPIVersions(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListAPIVersionsURL(endpoint, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listAPIVersionsVerbose,
		Silent:      listAPIVersionsSilent,
		IncludeResp: listAPIVersionsIncludeResp,
		UserAgent:   listAPIVersionsUserAgent,
	})
}

func buildListAPIVersionsURL(endpoint, version string) (string, error) {
	// Build base URL for the /openapi endpoint
	baseURL := fmt.Sprintf("https://%s/openapi", endpoint)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required for REST endpoints
	q.Set("version", version)

	u.RawQuery = q.Encode()
	return u.String(), nil
}
