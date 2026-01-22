package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteAppByIDCmd represents the delete-app-by-id command
var DeleteAppByIDCmd = &cobra.Command{
	Use:   "delete-app-by-id [org_id] [app_id]",
	Short: "Delete a specific app by ID from an organization",
	Long: `Delete a specific app by ID from an organization in the Snyk API.

This command deletes a specific app within an organization by providing both the 
organization ID and app ID as required arguments.

The organization ID and app ID must be provided as UUIDs.

Examples:
  snyk-api-cli delete-app-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli delete-app-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli delete-app-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteAppByID,
}

var (
	deleteAppByIDVerbose     bool
	deleteAppByIDSilent      bool
	deleteAppByIDIncludeResp bool
	deleteAppByIDUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteAppByIDCmd.Flags().BoolVarP(&deleteAppByIDVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteAppByIDCmd.Flags().BoolVarP(&deleteAppByIDSilent, "silent", "s", false, "Silent mode")
	DeleteAppByIDCmd.Flags().BoolVarP(&deleteAppByIDIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteAppByIDCmd.Flags().StringVarP(&deleteAppByIDUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteAppByID(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	appID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildDeleteAppByIDURL(endpoint, version, orgID, appID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteAppByIDVerbose,
		Silent:      deleteAppByIDSilent,
		IncludeResp: deleteAppByIDIncludeResp,
		UserAgent:   deleteAppByIDUserAgent,
	})
}

func buildDeleteAppByIDURL(endpoint, version, orgID, appID string) (string, error) {
	// Build base URL with org ID and app ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/creations/%s", endpoint, orgID, appID)

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
