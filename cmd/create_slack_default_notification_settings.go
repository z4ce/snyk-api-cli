package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateSlackDefaultNotificationSettingsCmd represents the create-slack-default-notification-settings command
var CreateSlackDefaultNotificationSettingsCmd = &cobra.Command{
	Use:   "create-slack-default-notification-settings [org_id] [bot_id]",
	Short: "Create new Slack notification default settings",
	Long: `Create new Slack notification default settings for a given tenant in the Snyk API.

This command creates default notification settings for a Slack integration in a specific
organization. The severity threshold and target channel ID must be provided as flags.

Examples:
  snyk-api-cli create-slack-default-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --severity-threshold high --target-channel-id "C1234567890"
  snyk-api-cli create-slack-default-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --severity-threshold critical --target-channel-id "C0987654321" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runCreateSlackDefaultNotificationSettings,
}

var (
	createSlackDefaultNotificationSettingsSeverityThreshold string
	createSlackDefaultNotificationSettingsTargetChannelID   string
	createSlackDefaultNotificationSettingsVerbose           bool
	createSlackDefaultNotificationSettingsSilent            bool
	createSlackDefaultNotificationSettingsIncludeResp       bool
	createSlackDefaultNotificationSettingsUserAgent         string
)

func init() {
	// Add flags for request body attributes
	CreateSlackDefaultNotificationSettingsCmd.Flags().StringVar(&createSlackDefaultNotificationSettingsSeverityThreshold, "severity-threshold", "", "Issue severity threshold: low, medium, high, or critical (required)")
	CreateSlackDefaultNotificationSettingsCmd.Flags().StringVar(&createSlackDefaultNotificationSettingsTargetChannelID, "target-channel-id", "", "Target Slack channel ID (required)")

	// Add standard flags like other commands
	CreateSlackDefaultNotificationSettingsCmd.Flags().BoolVarP(&createSlackDefaultNotificationSettingsVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateSlackDefaultNotificationSettingsCmd.Flags().BoolVarP(&createSlackDefaultNotificationSettingsSilent, "silent", "s", false, "Silent mode")
	CreateSlackDefaultNotificationSettingsCmd.Flags().BoolVarP(&createSlackDefaultNotificationSettingsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateSlackDefaultNotificationSettingsCmd.Flags().StringVarP(&createSlackDefaultNotificationSettingsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateSlackDefaultNotificationSettingsCmd.MarkFlagRequired("severity-threshold")
	CreateSlackDefaultNotificationSettingsCmd.MarkFlagRequired("target-channel-id")
}

func runCreateSlackDefaultNotificationSettings(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate severity threshold
	validSeverityThresholds := []string{"low", "medium", "high", "critical"}
	if !containsString(validSeverityThresholds, createSlackDefaultNotificationSettingsSeverityThreshold) {
		return fmt.Errorf("invalid severity-threshold: %s. Must be one of: %s", createSlackDefaultNotificationSettingsSeverityThreshold, strings.Join(validSeverityThresholds, ", "))
	}

	// Build the URL
	fullURL, err := buildCreateSlackDefaultNotificationSettingsURL(endpoint, version, orgID, botID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createSlackDefaultNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateSlackDefaultNotificationSettingsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createSlackDefaultNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createSlackDefaultNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createSlackDefaultNotificationSettingsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createSlackDefaultNotificationSettingsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createSlackDefaultNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createSlackDefaultNotificationSettingsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createSlackDefaultNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateSlackDefaultNotificationSettingsResponse(resp, createSlackDefaultNotificationSettingsIncludeResp, createSlackDefaultNotificationSettingsVerbose, createSlackDefaultNotificationSettingsSilent)
}

func buildCreateSlackDefaultNotificationSettingsURL(endpoint, version, orgID, botID string) (string, error) {
	// Build base URL with organization ID and bot ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s", endpoint, orgID, botID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add version parameter
	q := u.Query()
	q.Set("version", version)

	u.RawQuery = q.Encode()

	return u.String(), nil
}

func buildCreateSlackDefaultNotificationSettingsRequestBody() (string, error) {
	// Build attributes according to the API specification
	attributes := map[string]interface{}{
		"severity_threshold":  createSlackDefaultNotificationSettingsSeverityThreshold,
		"target_channel_id":   createSlackDefaultNotificationSettingsTargetChannelID,
	}

	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       "slack",
			"attributes": attributes,
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleCreateSlackDefaultNotificationSettingsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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

// Helper function to check if a slice contains a string
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}