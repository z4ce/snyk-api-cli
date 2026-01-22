package cmd

import (
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListImageTargetRefsCmd represents the list-image-target-refs command
var ListImageTargetRefsCmd = &cobra.Command{
	Use:   "list-image-target-refs [org_id] [image_id]",
	Short: "List image target references for a container image",
	Long: `List image target references for a container image in the Snyk API.

This command retrieves the list of image target references for a specific container image
within an organization. Image target references represent the different platforms and
targets where the container image can be used.

Examples:
  snyk-api-cli list-image-target-refs 12345678-1234-5678-9012-123456789012 img-12345678-1234-5678-9012-123456789012
  snyk-api-cli list-image-target-refs 12345678-1234-5678-9012-123456789012 img-12345678-1234-5678-9012-123456789012 --limit 10
  snyk-api-cli list-image-target-refs 12345678-1234-5678-9012-123456789012 img-12345678-1234-5678-9012-123456789012 --starting-after cursor123`,
	Args: cobra.ExactArgs(2),
	RunE: runListImageTargetRefs,
}

var (
	listImageTargetRefsLimit         int
	listImageTargetRefsStartingAfter string
	listImageTargetRefsEndingBefore  string
	listImageTargetRefsVerbose       bool
	listImageTargetRefsSilent        bool
	listImageTargetRefsIncludeResp   bool
	listImageTargetRefsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListImageTargetRefsCmd.Flags().IntVar(&listImageTargetRefsLimit, "limit", 0, "Number of results per page")
	ListImageTargetRefsCmd.Flags().StringVar(&listImageTargetRefsStartingAfter, "starting-after", "", "Cursor for pagination")
	ListImageTargetRefsCmd.Flags().StringVar(&listImageTargetRefsEndingBefore, "ending-before", "", "Cursor for pagination")
	
	// Add standard flags like curl command
	ListImageTargetRefsCmd.Flags().BoolVarP(&listImageTargetRefsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListImageTargetRefsCmd.Flags().BoolVarP(&listImageTargetRefsSilent, "silent", "s", false, "Silent mode")
	ListImageTargetRefsCmd.Flags().BoolVarP(&listImageTargetRefsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListImageTargetRefsCmd.Flags().StringVarP(&listImageTargetRefsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListImageTargetRefs(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	imageID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListImageTargetRefsURL(endpoint, version, orgID, imageID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "GET",
		URL:         fullURL,
		Verbose:     listImageTargetRefsVerbose,
		Silent:      listImageTargetRefsSilent,
		IncludeResp: listImageTargetRefsIncludeResp,
		UserAgent:   listImageTargetRefsUserAgent,
	})
}

func buildListImageTargetRefsURL(endpoint, version, orgID, imageID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/container_images/%s/relationships/image_target_refs", endpoint, orgID, imageID)

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
	if listImageTargetRefsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listImageTargetRefsLimit))
	}
	if listImageTargetRefsStartingAfter != "" {
		q.Set("starting_after", listImageTargetRefsStartingAfter)
	}
	if listImageTargetRefsEndingBefore != "" {
		q.Set("ending_before", listImageTargetRefsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}
