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

// CreateCustomBaseImageCmd represents the create-custom-base-image command
var CreateCustomBaseImageCmd = &cobra.Command{
	Use:   "create-custom-base-image",
	Short: "Create a custom base image in Snyk",
	Long: `Create a custom base image in the Snyk API.

This command creates a custom base image from a container project that can be used 
as a base image recommendation for upgrades.

Examples:
  snyk-api-cli create-custom-base-image --project-id 12345678-1234-5678-9012-123456789012 --include-recommendations
  snyk-api-cli create-custom-base-image --project-id 12345678-1234-5678-9012-123456789012 --include-recommendations --versioning-schema semantic`,
	RunE: runCreateCustomBaseImage,
}

var (
	createProjectID                string
	createIncludeInRecommendations bool
	createVersioningSchema         string
	createVerbose                  bool
	createSilent                   bool
	createIncludeResp              bool
	createUserAgent                string
)

func init() {
	// Add flags for request body attributes
	CreateCustomBaseImageCmd.Flags().StringVar(&createProjectID, "project-id", "", "Container project ID (required)")
	CreateCustomBaseImageCmd.Flags().BoolVar(&createIncludeInRecommendations, "include-recommendations", false, "Include in base image recommendations")
	CreateCustomBaseImageCmd.Flags().StringVar(&createVersioningSchema, "versioning-schema", "", "Versioning schema (optional)")
	
	// Add standard flags like curl command
	CreateCustomBaseImageCmd.Flags().BoolVarP(&createVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateCustomBaseImageCmd.Flags().BoolVarP(&createSilent, "silent", "s", false, "Silent mode")
	CreateCustomBaseImageCmd.Flags().BoolVarP(&createIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateCustomBaseImageCmd.Flags().StringVarP(&createUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	CreateCustomBaseImageCmd.MarkFlagRequired("project-id")
}

func runCreateCustomBaseImage(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateCustomBaseImageURL(endpoint, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if createVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildCreateCustomBaseImageRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if createVerbose {
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
	if createVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if createVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if createVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if createVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", createUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if createVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleCreateCustomBaseImageResponse(resp, createIncludeResp, createVerbose, createSilent)
}

func buildCreateCustomBaseImageURL(endpoint, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/custom_base_images", endpoint)

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

func buildCreateCustomBaseImageRequestBody() (string, error) {
	// Build JSON:API format request body
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "custom_base_image",
			"attributes": map[string]interface{}{
				"project_id":                 createProjectID,
				"include_in_recommendations": createIncludeInRecommendations,
			},
		},
	}

	// Add versioning schema if provided
	if createVersioningSchema != "" {
		attributes := requestData["data"].(map[string]interface{})["attributes"].(map[string]interface{})
		attributes["versioning_schema"] = createVersioningSchema
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleCreateCustomBaseImageResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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