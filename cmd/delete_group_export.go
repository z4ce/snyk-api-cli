package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteGroupExportCmd represents the delete-group-export command
var DeleteGroupExportCmd = &cobra.Command{
	Use:   "delete-group-export [group_id] [export_id]",
	Short: "Delete a group export by ID from Snyk",
	Long: `Delete a group export by ID from the Snyk API.

This command deletes a specific group export using its unique identifier.
Both group_id and export_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-group-export 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-export --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-export --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteGroupExport,
}

var (
	deleteGroupExportVerbose     bool
	deleteGroupExportSilent      bool
	deleteGroupExportIncludeResp bool
	deleteGroupExportUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteGroupExportCmd.Flags().BoolVarP(&deleteGroupExportVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteGroupExportCmd.Flags().BoolVarP(&deleteGroupExportSilent, "silent", "s", false, "Silent mode")
	DeleteGroupExportCmd.Flags().BoolVarP(&deleteGroupExportIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteGroupExportCmd.Flags().StringVarP(&deleteGroupExportUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteGroupExport(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	exportID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id and export_id path parameters
	fullURL, err := buildDeleteGroupExportURL(endpoint, groupID, exportID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteGroupExportVerbose,
		Silent:      deleteGroupExportSilent,
		IncludeResp: deleteGroupExportIncludeResp,
		UserAgent:   deleteGroupExportUserAgent,
	})
}

func buildDeleteGroupExportURL(endpoint, groupID, exportID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Validate the export_id parameter
	if strings.TrimSpace(exportID) == "" {
		return "", fmt.Errorf("export_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/export/%s", endpoint, groupID, exportID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add required version query parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}
