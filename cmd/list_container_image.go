package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListContainerImageCmd represents the list-container-image command
var ListContainerImageCmd = &cobra.Command{
	Use:   "list-container-image [org_id]",
	Short: "List container images from Snyk",
	Long: `List container images from the Snyk API for a specific organization.

This command retrieves a list of container images that the authenticated user can access
within the specified organization. The results can be filtered and paginated using various
query parameters.

Examples:
  snyk-api-cli list-container-image 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-container-image 12345678-1234-1234-1234-123456789012 --platform linux/amd64
  snyk-api-cli list-container-image 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-container-image 12345678-1234-1234-1234-123456789012 --image-ids img1,img2
  snyk-api-cli list-container-image 12345678-1234-1234-1234-123456789012 --names registry1,registry2
  snyk-api-cli list-container-image 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli list-container-image 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli list-container-image 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListContainerImage,
}

var (
	listContainerImagePlatform      string
	listContainerImageImageIDs      []string
	listContainerImageNames         []string
	listContainerImageLimit         int
	listContainerImageStartingAfter string
	listContainerImageEndingBefore  string
	listContainerImageVerbose       bool
	listContainerImageSilent        bool
	listContainerImageIncludeResp   bool
	listContainerImageUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListContainerImageCmd.Flags().StringVar(&listContainerImagePlatform, "platform", "", "Image Operating System and processor architecture (e.g. linux/amd64)")
	ListContainerImageCmd.Flags().StringSliceVar(&listContainerImageImageIDs, "image-ids", []string{}, "Comma-separated list of Image IDs")
	ListContainerImageCmd.Flags().StringSliceVar(&listContainerImageNames, "names", []string{}, "Container registry names (can be used multiple times)")
	ListContainerImageCmd.Flags().IntVar(&listContainerImageLimit, "limit", 0, "Number of results per page")
	ListContainerImageCmd.Flags().StringVar(&listContainerImageStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListContainerImageCmd.Flags().StringVar(&listContainerImageEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	ListContainerImageCmd.Flags().BoolVarP(&listContainerImageVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListContainerImageCmd.Flags().BoolVarP(&listContainerImageSilent, "silent", "s", false, "Silent mode")
	ListContainerImageCmd.Flags().BoolVarP(&listContainerImageIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListContainerImageCmd.Flags().StringVarP(&listContainerImageUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListContainerImage(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListContainerImageURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listContainerImageVerbose,
		Silent:      listContainerImageSilent,
		IncludeResp: listContainerImageIncludeResp,
		UserAgent:   listContainerImageUserAgent,
	})
}

func buildListContainerImageURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/container_images", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add optional parameters if provided
	if listContainerImagePlatform != "" {
		q.Set("platform", listContainerImagePlatform)
	}
	if len(listContainerImageImageIDs) > 0 {
		// Handle image_ids as comma-separated values
		q.Set("image_ids", strings.Join(listContainerImageImageIDs, ","))
	}
	if len(listContainerImageNames) > 0 {
		// Handle names as an array parameter
		for _, name := range listContainerImageNames {
			q.Add("names", name)
		}
	}
	if listContainerImageLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listContainerImageLimit))
	}
	if listContainerImageStartingAfter != "" {
		q.Set("starting_after", listContainerImageStartingAfter)
	}
	if listContainerImageEndingBefore != "" {
		q.Set("ending_before", listContainerImageEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
