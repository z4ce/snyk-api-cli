package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteAppCmd represents the delete-app command
var DeleteAppCmd = &cobra.Command{
	Use:   "delete-app [org_id] [client_id]",
	Short: "Delete an app from an organization",
	Long: `Delete an app from an organization in the Snyk API.

This command deletes a specific app within an organization by providing both the 
organization ID and client ID as required arguments.

The organization ID and client ID must be provided as UUIDs.

Note: This endpoint is deprecated. Consider using the newer app creation endpoints instead.

Examples:
  snyk-api-cli delete-app 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli delete-app 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli delete-app 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteApp,
}

var (
	deleteAppVerbose     bool
	deleteAppSilent      bool
	deleteAppIncludeResp bool
	deleteAppUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteAppCmd.Flags().BoolVarP(&deleteAppVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteAppCmd.Flags().BoolVarP(&deleteAppSilent, "silent", "s", false, "Silent mode")
	DeleteAppCmd.Flags().BoolVarP(&deleteAppIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteAppCmd.Flags().StringVarP(&deleteAppUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteApp(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	clientID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildDeleteAppURL(endpoint, version, orgID, clientID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteAppVerbose,
		Silent:      deleteAppSilent,
		IncludeResp: deleteAppIncludeResp,
		UserAgent:   deleteAppUserAgent,
	})
}

func buildDeleteAppURL(endpoint, version, orgID, clientID string) (string, error) {
	// Build base URL with org ID and client ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/%s", endpoint, orgID, clientID)

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
