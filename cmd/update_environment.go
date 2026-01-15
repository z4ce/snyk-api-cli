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

// UpdateEnvironmentCmd represents the update-environment command
var UpdateEnvironmentCmd = &cobra.Command{
	Use:   "update-environment [org_id] [environment_id]",
	Short: "Update an environment",
	Long: `Update an environment in the Snyk API.

This command updates an environment's details by providing the organization ID
and environment ID as required arguments. The environment name can be updated
via the --name flag.

The environment-id flag specifies the environment's ID (defaults to the environment_id argument).
The type flag specifies the content type (defaults to "environment").

Examples:
  snyk-api-cli update-environment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --name "Updated Environment"
  snyk-api-cli update-environment 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --name "New Environment Name" --verbose --include`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateEnvironment,
}

var (
	updateEnvironmentName        string
	updateEnvironmentEnvID       string
	updateEnvironmentType        string
	updateEnvironmentVerbose     bool
	updateEnvironmentSilent      bool
	updateEnvironmentIncludeResp bool
	updateEnvironmentUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateEnvironmentCmd.Flags().StringVar(&updateEnvironmentName, "name", "", "Environment name (required)")
	UpdateEnvironmentCmd.Flags().StringVar(&updateEnvironmentEnvID, "environment-id", "", "Environment's ID (optional, defaults to environment_id argument)")
	UpdateEnvironmentCmd.Flags().StringVar(&updateEnvironmentType, "type", "environment", "Content type for the environment (defaults to 'environment')")

	// Add standard flags like other commands
	UpdateEnvironmentCmd.Flags().BoolVarP(&updateEnvironmentVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateEnvironmentCmd.Flags().BoolVarP(&updateEnvironmentSilent, "silent", "s", false, "Silent mode")
	UpdateEnvironmentCmd.Flags().BoolVarP(&updateEnvironmentIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateEnvironmentCmd.Flags().StringVarP(&updateEnvironmentUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateEnvironmentCmd.MarkFlagRequired("name")
}

func runUpdateEnvironment(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	environmentID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Use environment ID from argument if not provided via flag
	if updateEnvironmentEnvID == "" {
		updateEnvironmentEnvID = environmentID
	}

	// Build the URL
	fullURL, err := buildUpdateEnvironmentURL(endpoint, version, orgID, environmentID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateEnvironmentVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateEnvironmentRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateEnvironmentVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("PATCH", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateEnvironmentVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateEnvironmentVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateEnvironmentVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateEnvironmentVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateEnvironmentUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateEnvironmentVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateEnvironmentResponse(resp, updateEnvironmentIncludeResp, updateEnvironmentVerbose, updateEnvironmentSilent)
}

func buildUpdateEnvironmentURL(endpoint, version, orgID, environmentID string) (string, error) {
	// Build base URL with org ID and environment ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/environments/%s", endpoint, orgID, environmentID)

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

func buildUpdateEnvironmentRequestBody() (string, error) {
	// Build JSON:API format request body according to the specification
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": updateEnvironmentType,
			"id":   updateEnvironmentEnvID,
			"attributes": map[string]interface{}{
				"name":    updateEnvironmentName,
				"options": nil, // Required as per API spec but undefined
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

func handleUpdateEnvironmentResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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