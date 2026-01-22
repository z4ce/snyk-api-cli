package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetUserCmd represents the get-user command
var GetUserCmd = &cobra.Command{
	Use:   "get-user [org_id] [id]",
	Short: "Get user by ID from Snyk",
	Long: `Get user by ID from the Snyk API.

This command retrieves detailed information about a specific user by their ID within an organization.
Both the organization ID and user ID must be provided as required arguments.

Required permissions: View users (org.user.read)

Examples:
  snyk-api-cli get-user 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-user 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli get-user 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetUser,
}

var (
	getUserVerbose     bool
	getUserSilent      bool
	getUserIncludeResp bool
	getUserUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetUserCmd.Flags().BoolVarP(&getUserVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetUserCmd.Flags().BoolVarP(&getUserSilent, "silent", "s", false, "Silent mode")
	GetUserCmd.Flags().BoolVarP(&getUserIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetUserCmd.Flags().StringVarP(&getUserUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetUser(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	userID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetUserURL(endpoint, version, orgID, userID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getUserVerbose,
		Silent:      getUserSilent,
		IncludeResp: getUserIncludeResp,
		UserAgent:   getUserUserAgent,
	})
}

func buildGetUserURL(endpoint, version, orgID, userID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(userID) == "" {
		return "", fmt.Errorf("user_id cannot be empty")
	}

	// Build base URL with organization ID and user ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/users/%s", endpoint, orgID, userID)

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
