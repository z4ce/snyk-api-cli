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

// UpdateCustomBaseImageCmd represents the update-custom-base-image command
var UpdateCustomBaseImageCmd = &cobra.Command{
	Use:   "update-custom-base-image [custombaseimage_id]",
	Short: "Update a custom base image in Snyk",
	Long: `Update a custom base image in the Snyk API.

This command updates an existing custom base image by its ID, allowing you to modify
whether it's included in recommendations and its versioning schema.

Examples:
  snyk-api-cli update-custom-base-image 12345678-1234-5678-9012-123456789012 --include-recommendations
  snyk-api-cli update-custom-base-image 12345678-1234-5678-9012-123456789012 --include-recommendations --versioning-schema semantic
  snyk-api-cli update-custom-base-image 12345678-1234-5678-9012-123456789012 --include-recommendations=false`,
	Args: cobra.ExactArgs(1),
	RunE: runUpdateCustomBaseImage,
}

var (
	updateIncludeInRecommendations bool
	updateVersioningSchema         string
	updateVerbose                  bool
	updateSilent                   bool
	updateIncludeResp              bool
	updateUserAgent                string
)

func init() {
	// Add flags for request body attributes
	UpdateCustomBaseImageCmd.Flags().BoolVar(&updateIncludeInRecommendations, "include-recommendations", false, "Include in base image recommendations")
	UpdateCustomBaseImageCmd.Flags().StringVar(&updateVersioningSchema, "versioning-schema", "", "Versioning schema")
	
	// Add standard flags like curl command
	UpdateCustomBaseImageCmd.Flags().BoolVarP(&updateVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateCustomBaseImageCmd.Flags().BoolVarP(&updateSilent, "silent", "s", false, "Silent mode")
	UpdateCustomBaseImageCmd.Flags().BoolVarP(&updateIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateCustomBaseImageCmd.Flags().StringVarP(&updateUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runUpdateCustomBaseImage(cmd *cobra.Command, args []string) error {
	customBaseImageID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateCustomBaseImageURL(endpoint, version, customBaseImageID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateCustomBaseImageRequestBody(customBaseImageID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateVerbose {
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
	if updateVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleUpdateCustomBaseImageResponse(resp, updateIncludeResp, updateVerbose, updateSilent)
}

func buildUpdateCustomBaseImageURL(endpoint, version, customBaseImageID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/custom_base_images/%s", endpoint, customBaseImageID)

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

func buildUpdateCustomBaseImageRequestBody(customBaseImageID string, cmd *cobra.Command) (string, error) {
	// Build JSON:API format request body
	requestData := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "custom_base_image",
			"id":   customBaseImageID,
			"attributes": map[string]interface{}{},
		},
	}

	attributes := requestData["data"].(map[string]interface{})["attributes"].(map[string]interface{})

	// Add include_in_recommendations if flag was explicitly set
	if cmd.Flags().Changed("include-recommendations") {
		attributes["include_in_recommendations"] = updateIncludeInRecommendations
	}

	// Add versioning schema if provided
	if updateVersioningSchema != "" {
		attributes["versioning_schema"] = updateVersioningSchema
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleUpdateCustomBaseImageResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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