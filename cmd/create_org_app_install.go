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

// CreateOrgAppInstallCmd represents the create-org-app-install command
var CreateOrgAppInstallCmd = &cobra.Command{
	Use:   "create-org-app-install [org_id]",
	Short: "Create an app installation for a specific organization in Snyk",
	Long: `Create an app installation for a specific organization in the Snyk API.

This command creates an app installation for a specific organization by its ID.
The organization ID must be provided as a required argument, and the app ID 
must be provided as a flag.

Examples:
  snyk-api-cli create-org-app-install 12345678-1234-1234-1234-123456789012 --app-id 87654321-4321-4321-4321-210987654321
  snyk-api-cli create-org-app-install 12345678-1234-1234-1234-123456789012 --app-id 87654321-4321-4321-4321-210987654321 --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateOrgAppInstall,
}

var (
	createOrgAppInstallAppID       string
	createOrgAppInstallVerbose     bool
	createOrgAppInstallSilent      bool
	createOrgAppInstallIncludeResp bool
	createOrgAppInstallUserAgent   string
)

func init() {
	// Add flags for request body attributes
	CreateOrgAppInstallCmd.Flags().StringVar(&createOrgAppInstallAppID, "app-id", "", "App ID to install (required)")
	
	// Add standard flags like other commands
	CreateOrgAppInstallCmd.Flags().BoolVarP(&createOrgAppInstallVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateOrgAppInstallCmd.Flags().BoolVarP(&createOrgAppInstallSilent, "silent", "s", false, "Silent mode")
	CreateOrgAppInstallCmd.Flags().BoolVarP(&createOrgAppInstallIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateOrgAppInstallCmd.Flags().StringVarP(&createOrgAppInstallUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateOrgAppInstallCmd.MarkFlagRequired("app-id")
}

func runCreateOrgAppInstall(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateOrgAppInstallURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createOrgAppInstallVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateOrgAppInstallRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createOrgAppInstallVerbose {
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
	if createOrgAppInstallVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createOrgAppInstallVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createOrgAppInstallVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createOrgAppInstallVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createOrgAppInstallUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createOrgAppInstallVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateOrgAppInstallResponse(resp, createOrgAppInstallIncludeResp, createOrgAppInstallVerbose, createOrgAppInstallSilent)
}

func buildCreateOrgAppInstallURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with org ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/installs", endpoint, orgID)

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

func buildCreateOrgAppInstallRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "app_install",
			"relationships": map[string]interface{}{
				"app": map[string]interface{}{
					"data": map[string]interface{}{
						"id":   createOrgAppInstallAppID,
						"type": "app",
					},
				},
			},
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleCreateOrgAppInstallResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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