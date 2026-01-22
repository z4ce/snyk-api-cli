package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetContainerImageCmd represents the get-container-image command
var GetContainerImageCmd = &cobra.Command{
	Use:   "get-container-image [org_id] [image_id]",
	Short: "Get a container image by ID from Snyk",
	Long: `Get a container image by ID from the Snyk API.

This command retrieves detailed information about a specific container image by its ID within an organization.
Both the organization ID and image ID must be provided as required arguments.

Required permissions: View container images (org.container_image.read)

Examples:
  snyk-api-cli get-container-image 12345678-1234-1234-1234-123456789012 sha256:abcdef123456
  snyk-api-cli get-container-image 12345678-1234-1234-1234-123456789012 sha256:abcdef123456 --verbose
  snyk-api-cli get-container-image 12345678-1234-1234-1234-123456789012 sha256:abcdef123456 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetContainerImage,
}

var (
	getContainerImageVerbose     bool
	getContainerImageSilent      bool
	getContainerImageIncludeResp bool
	getContainerImageUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetContainerImageCmd.Flags().BoolVarP(&getContainerImageVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetContainerImageCmd.Flags().BoolVarP(&getContainerImageSilent, "silent", "s", false, "Silent mode")
	GetContainerImageCmd.Flags().BoolVarP(&getContainerImageIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetContainerImageCmd.Flags().StringVarP(&getContainerImageUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetContainerImage(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	imageID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetContainerImageURL(endpoint, version, orgID, imageID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     getContainerImageVerbose,
		Silent:      getContainerImageSilent,
		IncludeResp: getContainerImageIncludeResp,
		UserAgent:   getContainerImageUserAgent,
	})
}

func buildGetContainerImageURL(endpoint, version, orgID, imageID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(imageID) == "" {
		return "", fmt.Errorf("image_id cannot be empty")
	}

	// Build base URL with organization ID and image ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/container_images/%s", endpoint, orgID, imageID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	u.RawQuery = q.Encode()
	return u.String(), nil
}
