package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateScanCmd represents the create-scan command
var CreateScanCmd = &cobra.Command{
	Use:   "create-scan [org_id]",
	Short: "Create a new cloud scan for an organization",
	Long: `Create a new cloud scan for an organization in the Snyk API.

This command creates and triggers a new scan for a cloud environment within 
the specified organization. The scan requires an environment ID and can 
optionally include additional attributes.

Examples:
  snyk-api-cli create-scan 12345678-1234-1234-1234-123456789012 --environment-id env-12345 --type cloud_scan
  snyk-api-cli create-scan 12345678-1234-1234-1234-123456789012 --environment-id env-12345 --type cloud_scan --attributes '{"key":"value"}' --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateScan,
}

var (
	createScanType          string
	createScanEnvironmentID string
	createScanAttributes    string
	createScanVerbose       bool
	createScanSilent        bool
	createScanIncludeResp   bool
	createScanUserAgent     string
)

func init() {
	// Add flags for request body attributes
	CreateScanCmd.Flags().StringVar(&createScanType, "type", "cloud_scan", "Scan type (default: cloud_scan)")
	CreateScanCmd.Flags().StringVar(&createScanEnvironmentID, "environment-id", "", "Environment ID (required)")
	CreateScanCmd.Flags().StringVar(&createScanAttributes, "attributes", "{}", "Additional scan attributes as JSON string (optional)")

	// Add standard flags like other commands
	CreateScanCmd.Flags().BoolVarP(&createScanVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateScanCmd.Flags().BoolVarP(&createScanSilent, "silent", "s", false, "Silent mode")
	CreateScanCmd.Flags().BoolVarP(&createScanIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateScanCmd.Flags().StringVarP(&createScanUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateScanCmd.MarkFlagRequired("environment-id")
}

func runCreateScan(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate required parameters
	if strings.TrimSpace(createScanEnvironmentID) == "" {
		return fmt.Errorf("environment-id is required")
	}

	// Build the full URL
	fullURL, err := buildCreateScanURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateScanRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        string(requestBody),
		ContentType: "application/vnd.api+json",
		Verbose:     createScanVerbose,
		Silent:      createScanSilent,
		IncludeResp: createScanIncludeResp,
		UserAgent:   createScanUserAgent,
	})
}

func buildCreateScanURL(endpoint, version, orgID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/scans", endpoint, orgID)

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

func buildCreateScanRequestBody() ([]byte, error) {
	// Parse attributes JSON if provided
	var attributes interface{}
	if createScanAttributes != "" {
		if err := json.Unmarshal([]byte(createScanAttributes), &attributes); err != nil {
			return nil, fmt.Errorf("invalid attributes JSON: %w", err)
		}
	} else {
		attributes = map[string]interface{}{}
	}

	// Build request body according to API schema
	requestBody := map[string]interface{}{
		"data": map[string]interface{}{
			"type":       createScanType,
			"attributes": attributes,
			"relationships": map[string]interface{}{
				"environment": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   createScanEnvironmentID,
						"type": "environment",
					},
				},
			},
		},
	}

	// Marshal to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	return jsonBody, nil
}
