package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

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

	// Build request body
	requestBody, err := buildCreateCustomBaseImageRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createVerbose,
		Silent:      createSilent,
		IncludeResp: createIncludeResp,
		UserAgent:   createUserAgent,
	})
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
