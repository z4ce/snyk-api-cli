package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteSlackProjectNotificationSettingsCmd represents the delete-slack-project-notification-settings command
var DeleteSlackProjectNotificationSettingsCmd = &cobra.Command{
	Use:   "delete-slack-project-notification-settings [org_id] [bot_id] [project_id]",
	Short: "Remove Slack settings override for a project",
	Long: `Remove Slack settings override for a project from the Snyk API.

This command removes Slack notification settings override for a specific project
in an organization. The organization ID, bot ID, and project ID must be provided.

Examples:
  snyk-api-cli delete-slack-project-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11223344-5566-7788-9900-112233445566
  snyk-api-cli delete-slack-project-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11223344-5566-7788-9900-112233445566 --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runDeleteSlackProjectNotificationSettings,
}

var (
	deleteSlackProjectNotificationSettingsVerbose     bool
	deleteSlackProjectNotificationSettingsSilent      bool
	deleteSlackProjectNotificationSettingsIncludeResp bool
	deleteSlackProjectNotificationSettingsUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&deleteSlackProjectNotificationSettingsVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&deleteSlackProjectNotificationSettingsSilent, "silent", "s", false, "Silent mode")
	DeleteSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&deleteSlackProjectNotificationSettingsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteSlackProjectNotificationSettingsCmd.Flags().StringVarP(&deleteSlackProjectNotificationSettingsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteSlackProjectNotificationSettings(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	projectID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildDeleteSlackProjectNotificationSettingsURL(endpoint, version, orgID, botID, projectID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteSlackProjectNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteSlackProjectNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteSlackProjectNotificationSettingsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteSlackProjectNotificationSettingsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteSlackProjectNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteSlackProjectNotificationSettingsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteSlackProjectNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteSlackProjectNotificationSettingsResponse(resp, deleteSlackProjectNotificationSettingsIncludeResp, deleteSlackProjectNotificationSettingsVerbose, deleteSlackProjectNotificationSettingsSilent)
}

func buildDeleteSlackProjectNotificationSettingsURL(endpoint, version, orgID, botID, projectID string) (string, error) {
	// Build base URL with org ID, bot ID, and project ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s/projects/%s", endpoint, orgID, botID, projectID)

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

func handleDeleteSlackProjectNotificationSettingsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
	if verbose {
		fmt.Fprintf(os.Stderr, "* Response: %s\n", resp.Status)
	}

	// Print response headers if requested
	if includeResp {
		fmt.Printf("%s %s\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
		fmt.Println()
	}

	// Read and print response body (even for DELETE, in case there's error info)
	if !silent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		if len(body) > 0 {
			fmt.Print(string(body))
		}
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}