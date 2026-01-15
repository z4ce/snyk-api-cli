package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetSlackProjectNotificationSettingsCollectionCmd represents the get-slack-project-notification-settings-collection command
var GetSlackProjectNotificationSettingsCollectionCmd = &cobra.Command{
	Use:   "get-slack-project-notification-settings-collection [org_id] [bot_id]",
	Short: "Slack notification settings overrides for projects",
	Long: `Get Slack notification settings overrides for projects from the Snyk API.

This command retrieves a collection of Slack notification settings overrides for projects
in a specific organization. Both organization ID and bot ID must be provided.

Examples:
  snyk-api-cli get-slack-project-notification-settings-collection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-slack-project-notification-settings-collection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 50
  snyk-api-cli get-slack-project-notification-settings-collection 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --starting-after "cursor123" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runGetSlackProjectNotificationSettingsCollection,
}

var (
	getSlackProjectNotificationSettingsCollectionStartingAfter string
	getSlackProjectNotificationSettingsCollectionEndingBefore  string
	getSlackProjectNotificationSettingsCollectionLimit         int
	getSlackProjectNotificationSettingsCollectionVerbose       bool
	getSlackProjectNotificationSettingsCollectionSilent        bool
	getSlackProjectNotificationSettingsCollectionIncludeResp   bool
	getSlackProjectNotificationSettingsCollectionUserAgent     string
)

func init() {
	// Add pagination flags
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().StringVar(&getSlackProjectNotificationSettingsCollectionStartingAfter, "starting-after", "", "Cursor for pagination - results after this cursor")
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().StringVar(&getSlackProjectNotificationSettingsCollectionEndingBefore, "ending-before", "", "Cursor for pagination - results before this cursor")
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().IntVar(&getSlackProjectNotificationSettingsCollectionLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().BoolVarP(&getSlackProjectNotificationSettingsCollectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().BoolVarP(&getSlackProjectNotificationSettingsCollectionSilent, "silent", "s", false, "Silent mode")
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().BoolVarP(&getSlackProjectNotificationSettingsCollectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetSlackProjectNotificationSettingsCollectionCmd.Flags().StringVarP(&getSlackProjectNotificationSettingsCollectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetSlackProjectNotificationSettingsCollection(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetSlackProjectNotificationSettingsCollectionURL(endpoint, version, orgID, botID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getSlackProjectNotificationSettingsCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getSlackProjectNotificationSettingsCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getSlackProjectNotificationSettingsCollectionVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getSlackProjectNotificationSettingsCollectionVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getSlackProjectNotificationSettingsCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getSlackProjectNotificationSettingsCollectionUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getSlackProjectNotificationSettingsCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetSlackProjectNotificationSettingsCollectionResponse(resp, getSlackProjectNotificationSettingsCollectionIncludeResp, getSlackProjectNotificationSettingsCollectionVerbose, getSlackProjectNotificationSettingsCollectionSilent)
}

func buildGetSlackProjectNotificationSettingsCollectionURL(endpoint, version, orgID, botID string) (string, error) {
	// Build base URL with org ID and bot ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s/projects", endpoint, orgID, botID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add pagination parameters if specified
	if getSlackProjectNotificationSettingsCollectionStartingAfter != "" {
		q.Set("starting_after", getSlackProjectNotificationSettingsCollectionStartingAfter)
	}
	if getSlackProjectNotificationSettingsCollectionEndingBefore != "" {
		q.Set("ending_before", getSlackProjectNotificationSettingsCollectionEndingBefore)
	}
	if getSlackProjectNotificationSettingsCollectionLimit > 0 {
		q.Set("limit", strconv.Itoa(getSlackProjectNotificationSettingsCollectionLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetSlackProjectNotificationSettingsCollectionResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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

	// Read and print response body
	if !silent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		fmt.Print(string(body))
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}