package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

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

	if listImageTargetRefsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listImageTargetRefsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listImageTargetRefsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listImageTargetRefsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listImageTargetRefsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listImageTargetRefsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listImageTargetRefsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleListImageTargetRefsResponse(resp, listImageTargetRefsIncludeResp, listImageTargetRefsVerbose, listImageTargetRefsSilent)
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

func handleListImageTargetRefsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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