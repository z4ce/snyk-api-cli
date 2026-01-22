package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetCustomBaseImageCmd represents the get-custom-base-image command
var GetCustomBaseImageCmd = &cobra.Command{
	Use:   "get-custom-base-image [custombaseimage_id]",
	Short: "Get a custom base image by ID from Snyk",
	Long: `Get a custom base image by ID from the Snyk API.

This command retrieves a specific custom base image using its unique identifier.
The custombaseimage_id parameter is required and must be a valid UUID.

Examples:
  snyk-api-cli get-custom-base-image 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-custom-base-image --verbose 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-custom-base-image --include 12345678-1234-5678-9012-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runGetCustomBaseImage,
}

var (
	getCustomBaseImageVerbose     bool
	getCustomBaseImageSilent      bool
	getCustomBaseImageIncludeResp bool
	getCustomBaseImageUserAgent   string
)

func init() {
	// Add standard flags like curl command
	GetCustomBaseImageCmd.Flags().BoolVarP(&getCustomBaseImageVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetCustomBaseImageCmd.Flags().BoolVarP(&getCustomBaseImageSilent, "silent", "s", false, "Silent mode")
	GetCustomBaseImageCmd.Flags().BoolVarP(&getCustomBaseImageIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetCustomBaseImageCmd.Flags().StringVarP(&getCustomBaseImageUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetCustomBaseImage(cmd *cobra.Command, args []string) error {
	customBaseImageID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the custombaseimage_id path parameter
	fullURL, err := buildGetCustomBaseImageURL(endpoint, customBaseImageID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getCustomBaseImageVerbose,
		Silent:      getCustomBaseImageSilent,
		IncludeResp: getCustomBaseImageIncludeResp,
		UserAgent:   getCustomBaseImageUserAgent,
	})
}

func buildGetCustomBaseImageURL(endpoint, customBaseImageID, version string) (string, error) {
	// Validate the custombaseimage_id parameter
	if strings.TrimSpace(customBaseImageID) == "" {
		return "", fmt.Errorf("custombaseimage_id cannot be empty")
	}

	// Build base URL with the path parameter
	baseURL := fmt.Sprintf("https://%s/rest/custom_base_images/%s", endpoint, customBaseImageID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add required version query parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}
