package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteCustomBaseImageCmd represents the delete-custom-base-image command
var DeleteCustomBaseImageCmd = &cobra.Command{
	Use:   "delete-custom-base-image [custombaseimage_id]",
	Short: "Delete a custom base image by ID from Snyk",
	Long: `Delete a custom base image by ID from the Snyk API.

This command deletes a specific custom base image using its unique identifier.
The custombaseimage_id parameter is required and must be a valid UUID.
Note: This does not affect the related container project.

Examples:
  snyk-api-cli delete-custom-base-image 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-custom-base-image --verbose 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-custom-base-image --include 12345678-1234-5678-9012-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runDeleteCustomBaseImage,
}

var (
	deleteCustomBaseImageVerbose     bool
	deleteCustomBaseImageSilent      bool
	deleteCustomBaseImageIncludeResp bool
	deleteCustomBaseImageUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteCustomBaseImageCmd.Flags().BoolVarP(&deleteCustomBaseImageVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteCustomBaseImageCmd.Flags().BoolVarP(&deleteCustomBaseImageSilent, "silent", "s", false, "Silent mode")
	DeleteCustomBaseImageCmd.Flags().BoolVarP(&deleteCustomBaseImageIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteCustomBaseImageCmd.Flags().StringVarP(&deleteCustomBaseImageUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteCustomBaseImage(cmd *cobra.Command, args []string) error {
	customBaseImageID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the custombaseimage_id path parameter
	fullURL, err := buildDeleteCustomBaseImageURL(endpoint, customBaseImageID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Verbose:     deleteCustomBaseImageVerbose,
		Silent:      deleteCustomBaseImageSilent,
		IncludeResp: deleteCustomBaseImageIncludeResp,
		UserAgent:   deleteCustomBaseImageUserAgent,
	})
}

func buildDeleteCustomBaseImageURL(endpoint, customBaseImageID, version string) (string, error) {
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
