package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteAppBotCmd represents the delete-app-bot command
var DeleteAppBotCmd = &cobra.Command{
	Use:   "delete-app-bot [org_id] [bot_id]",
	Short: "Delete an app bot by ID from Snyk",
	Long: `Delete an app bot by ID from the Snyk API.

This command deletes a specific app bot using its unique identifier within an organization.
Both org_id and bot_id parameters are required and must be valid UUIDs.

Note: This endpoint is deprecated. Consider using /orgs/{org_id}/apps/installs/{install_id} instead.

Examples:
  snyk-api-cli delete-app-bot 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-app-bot --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-app-bot --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteAppBot,
}

var (
	deleteAppBotVerbose     bool
	deleteAppBotSilent      bool
	deleteAppBotIncludeResp bool
	deleteAppBotUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteAppBotCmd.Flags().BoolVarP(&deleteAppBotVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteAppBotCmd.Flags().BoolVarP(&deleteAppBotSilent, "silent", "s", false, "Silent mode")
	DeleteAppBotCmd.Flags().BoolVarP(&deleteAppBotIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteAppBotCmd.Flags().StringVarP(&deleteAppBotUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteAppBot(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and bot_id path parameters
	fullURL, err := buildDeleteAppBotURL(endpoint, orgID, botID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteAppBotVerbose,
		Silent:      deleteAppBotSilent,
		IncludeResp: deleteAppBotIncludeResp,
		UserAgent:   deleteAppBotUserAgent,
	})
}

func buildDeleteAppBotURL(endpoint, orgID, botID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the bot_id parameter
	if strings.TrimSpace(botID) == "" {
		return "", fmt.Errorf("bot_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/app_bots/%s", endpoint, orgID, botID)

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
