package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetGroupExportCmd represents the get-group-export command
var GetGroupExportCmd = &cobra.Command{
	Use:   "get-group-export [group_id] [export_id]",
	Short: "Get details of a specific group export from Snyk",
	Long: `Get details of a specific group export from the Snyk API.

This command retrieves detailed information about a specific group export by its group ID and export ID.
Both the group ID and export ID must be provided as required arguments.

Examples:
  snyk-api-cli get-group-export 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-group-export 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-group-export 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetGroupExport,
}

var (
	getGroupExportVerbose     bool
	getGroupExportSilent      bool
	getGroupExportIncludeResp bool
	getGroupExportUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetGroupExportCmd.Flags().BoolVarP(&getGroupExportVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetGroupExportCmd.Flags().BoolVarP(&getGroupExportSilent, "silent", "s", false, "Silent mode")
	GetGroupExportCmd.Flags().BoolVarP(&getGroupExportIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetGroupExportCmd.Flags().StringVarP(&getGroupExportUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetGroupExport(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	exportID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetGroupExportURL(endpoint, version, groupID, exportID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getGroupExportVerbose,
		Silent:      getGroupExportSilent,
		IncludeResp: getGroupExportIncludeResp,
		UserAgent:   getGroupExportUserAgent,
	})
}

func buildGetGroupExportURL(endpoint, version, groupID, exportID string) (string, error) {
	// Build base URL with group ID and export ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/export/%s", endpoint, groupID, exportID)

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
