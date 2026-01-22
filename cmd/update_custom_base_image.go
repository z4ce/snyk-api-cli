package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

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

	// Build request body
	requestBody, err := buildUpdateCustomBaseImageRequestBody(customBaseImageID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateVerbose,
		Silent:      updateSilent,
		IncludeResp: updateIncludeResp,
		UserAgent:   updateUserAgent,
	})
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
