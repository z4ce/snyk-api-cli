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

// CreateEnvironmentCmd represents the create-environment command
var CreateEnvironmentCmd = &cobra.Command{
	Use:   "create-environment [org_id]",
	Short: "Create a new cloud environment for an organization",
	Long: `Create a new cloud environment for an organization in the Snyk API.

This command creates a new cloud environment that belongs to the specified organization.
The environment requires a kind (aws, google, azure, scm, tfc, cli) and can optionally
include a name and additional options.

Examples:
  snyk-api-cli create-environment 12345678-1234-1234-1234-123456789012 --kind aws --name "Production AWS"
  snyk-api-cli create-environment 12345678-1234-1234-1234-123456789012 --kind google --name "Dev Environment"
  snyk-api-cli create-environment 12345678-1234-1234-1234-123456789012 --kind azure --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateEnvironment,
}

var (
	createEnvKind        string
	createEnvName        string
	createEnvOptions     string
	createEnvVerbose     bool
	createEnvSilent      bool
	createEnvIncludeResp bool
	createEnvUserAgent   string
)

func init() {
	// Add flags for request body attributes
	CreateEnvironmentCmd.Flags().StringVar(&createEnvKind, "kind", "", "Environment kind (required: aws, google, azure, scm, tfc, cli)")
	CreateEnvironmentCmd.Flags().StringVar(&createEnvName, "name", "", "Environment name (optional)")
	CreateEnvironmentCmd.Flags().StringVar(&createEnvOptions, "options", "{}", "Environment options as JSON string (optional)")

	// Add standard flags like other commands
	CreateEnvironmentCmd.Flags().BoolVarP(&createEnvVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateEnvironmentCmd.Flags().BoolVarP(&createEnvSilent, "silent", "s", false, "Silent mode")
	CreateEnvironmentCmd.Flags().BoolVarP(&createEnvIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateEnvironmentCmd.Flags().StringVarP(&createEnvUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateEnvironmentCmd.MarkFlagRequired("kind")
}

func runCreateEnvironment(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Validate required parameters
	if strings.TrimSpace(createEnvKind) == "" {
		return fmt.Errorf("kind is required")
	}

	// Validate kind value
	validKinds := []string{"aws", "google", "azure", "scm", "tfc", "cli"}
	kindValid := false
	for _, validKind := range validKinds {
		if createEnvKind == validKind {
			kindValid = true
			break
		}
	}
	if !kindValid {
		return fmt.Errorf("invalid kind '%s', must be one of: %s", createEnvKind, strings.Join(validKinds, ", "))
	}

	// Build the full URL
	fullURL, err := buildCreateEnvironmentURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createEnvVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateEnvironmentRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createEnvVerbose {
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
	if createEnvVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createEnvVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createEnvVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createEnvVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createEnvUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createEnvVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleCreateEnvironmentResponse(resp, createEnvIncludeResp, createEnvVerbose, createEnvSilent)
}

func buildCreateEnvironmentURL(endpoint, version, orgID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/cloud/environments", endpoint, orgID)

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

func buildCreateEnvironmentRequestBody() ([]byte, error) {
	// Parse options JSON if provided
	var options interface{}
	if createEnvOptions != "" {
		if err := json.Unmarshal([]byte(createEnvOptions), &options); err != nil {
			return nil, fmt.Errorf("invalid options JSON: %w", err)
		}
	} else {
		options = map[string]interface{}{}
	}

	// Build request body according to API schema
	requestBody := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "environment",
			"attributes": map[string]interface{}{
				"kind":    createEnvKind,
				"options": options,
			},
		},
	}

	// Add name if provided
	if strings.TrimSpace(createEnvName) != "" {
		requestBody["data"].(map[string]interface{})["attributes"].(map[string]interface{})["name"] = createEnvName
	}

	// Marshal to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	return jsonBody, nil
}

func handleCreateEnvironmentResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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