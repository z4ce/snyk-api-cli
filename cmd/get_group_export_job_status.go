package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetGroupExportJobStatusCmd represents the get-group-export-job-status command
var GetGroupExportJobStatusCmd = &cobra.Command{
	Use:   "get-group-export-job-status [group_id] [export_id]",
	Short: "Get the status of a group export job from Snyk",
	Long: `Get the status of a group export job from the Snyk API.

This command retrieves the status of a specific group export job by its group ID and export ID.
Both the group ID and export ID must be provided as required arguments.

The response will include the job status which can be one of: PENDING, FINISHED, ERRORED, STARTED.

Examples:
  snyk-api-cli get-group-export-job-status 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-group-export-job-status 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-group-export-job-status 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetGroupExportJobStatus,
}

var (
	getGroupExportJobStatusVerbose     bool
	getGroupExportJobStatusSilent      bool
	getGroupExportJobStatusIncludeResp bool
	getGroupExportJobStatusUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetGroupExportJobStatusCmd.Flags().BoolVarP(&getGroupExportJobStatusVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetGroupExportJobStatusCmd.Flags().BoolVarP(&getGroupExportJobStatusSilent, "silent", "s", false, "Silent mode")
	GetGroupExportJobStatusCmd.Flags().BoolVarP(&getGroupExportJobStatusIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetGroupExportJobStatusCmd.Flags().StringVarP(&getGroupExportJobStatusUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetGroupExportJobStatus(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	exportID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetGroupExportJobStatusURL(endpoint, version, groupID, exportID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getGroupExportJobStatusVerbose,
		Silent:      getGroupExportJobStatusSilent,
		IncludeResp: getGroupExportJobStatusIncludeResp,
		UserAgent:   getGroupExportJobStatusUserAgent,
	})
}

func buildGetGroupExportJobStatusURL(endpoint, version, groupID, exportID string) (string, error) {
	// Build base URL with group ID and export ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/jobs/export/%s", endpoint, groupID, exportID)

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
