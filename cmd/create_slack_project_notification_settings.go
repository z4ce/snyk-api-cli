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

// CreateSlackProjectNotificationSettingsCmd represents the create-slack-project-notification-settings command
var CreateSlackProjectNotificationSettingsCmd = &cobra.Command{
	Use:   "create-slack-project-notification-settings [org_id] [bot_id] [project_id]",
	Short: "Create a new Slack settings override for a given project",
	Long: `Create a new Slack settings override for a given project in the Snyk API.

This command creates Slack notification settings override for a specific project
in an organization. The organization ID, bot ID, project ID, severity threshold, 
and target channel ID must be provided.

Examples:
  snyk-api-cli create-slack-project-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11223344-5566-7788-9900-112233445566 --severity-threshold high --target-channel-id "C1234567890"
  snyk-api-cli create-slack-project-notification-settings 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 11223344-5566-7788-9900-112233445566 --severity-threshold critical --target-channel-id "C0987654321" --verbose`,
	Args: cobra.ExactArgs(3),
	RunE: runCreateSlackProjectNotificationSettings,
}

var (
	createSlackProjectNotificationSettingsSeverityThreshold string
	createSlackProjectNotificationSettingsTargetChannelID   string
	createSlackProjectNotificationSettingsVerbose           bool
	createSlackProjectNotificationSettingsSilent            bool
	createSlackProjectNotificationSettingsIncludeResp       bool
	createSlackProjectNotificationSettingsUserAgent         string
)

func init() {
	// Add flags for request body attributes
	CreateSlackProjectNotificationSettingsCmd.Flags().StringVar(&createSlackProjectNotificationSettingsSeverityThreshold, "severity-threshold", "", "Issue severity threshold: low, medium, high, or critical (required)")
	CreateSlackProjectNotificationSettingsCmd.Flags().StringVar(&createSlackProjectNotificationSettingsTargetChannelID, "target-channel-id", "", "Target Slack channel ID (required)")

	// Add standard flags like other commands
	CreateSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&createSlackProjectNotificationSettingsVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&createSlackProjectNotificationSettingsSilent, "silent", "s", false, "Silent mode")
	CreateSlackProjectNotificationSettingsCmd.Flags().BoolVarP(&createSlackProjectNotificationSettingsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateSlackProjectNotificationSettingsCmd.Flags().StringVarP(&createSlackProjectNotificationSettingsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateSlackProjectNotificationSettingsCmd.MarkFlagRequired("severity-threshold")
	CreateSlackProjectNotificationSettingsCmd.MarkFlagRequired("target-channel-id")
}

func runCreateSlackProjectNotificationSettings(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	botID := args[1]
	projectID := args[2]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate severity threshold
	validSeverityThresholds := []string{"low", "medium", "high", "critical"}
	if !containsStringItem(validSeverityThresholds, createSlackProjectNotificationSettingsSeverityThreshold) {
		return fmt.Errorf("invalid severity-threshold: %s. Must be one of: %s", createSlackProjectNotificationSettingsSeverityThreshold, strings.Join(validSeverityThresholds, ", "))
	}

	// Build the URL
	fullURL, err := buildCreateSlackProjectNotificationSettingsURL(endpoint, version, orgID, botID, projectID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createSlackProjectNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateSlackProjectNotificationSettingsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createSlackProjectNotificationSettingsVerbose {
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
	if createSlackProjectNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createSlackProjectNotificationSettingsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createSlackProjectNotificationSettingsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createSlackProjectNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createSlackProjectNotificationSettingsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createSlackProjectNotificationSettingsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateSlackProjectNotificationSettingsResponse(resp, createSlackProjectNotificationSettingsIncludeResp, createSlackProjectNotificationSettingsVerbose, createSlackProjectNotificationSettingsSilent)
}

func buildCreateSlackProjectNotificationSettingsURL(endpoint, version, orgID, botID, projectID string) (string, error) {
	// Build base URL with organization ID, bot ID, and project ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s/projects/%s", endpoint, orgID, botID, projectID)

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

func buildCreateSlackProjectNotificationSettingsRequestBody() (string, error) {
	// Build attributes according to the API specification
	attributes := map[string]interface{}{
		"severity_threshold": createSlackProjectNotificationSettingsSeverityThreshold,
		"target_channel_id":  createSlackProjectNotificationSettingsTargetChannelID,
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

func handleCreateSlackProjectNotificationSettingsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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

// Helper function to check if a slice contains a string (avoiding conflict with existing contains function)
func containsStringItem(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}