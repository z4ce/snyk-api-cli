package cmd

import (
	"bytes"
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
	createScanType           string
	createScanEnvironmentID  string
	createScanAttributes     string
	createScanVerbose        bool
	createScanSilent         bool
	createScanIncludeResp    bool
	createScanUserAgent      string
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

	if createScanVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateScanRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createScanVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", string(requestBody))
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if createScanVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createScanVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createScanVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createScanVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createScanUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createScanVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateScanResponse(resp, createScanIncludeResp, createScanVerbose, createScanSilent)
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

func handleCreateScanResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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