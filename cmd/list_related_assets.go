package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListRelatedAssetsCmd represents the list-related-assets command
var ListRelatedAssetsCmd = &cobra.Command{
	Use:   "list-related-assets [group_id] [asset_id]",
	Short: "List assets related to a specific asset in a group",
	Long: `List assets related to a specific asset in a group from the Snyk API.

This command retrieves assets that are related to a specific asset within a group.
Both the group ID and asset ID must be provided as required arguments.
Various query parameters can be used to filter and paginate the results.

Examples:
  snyk-api-cli list-related-assets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-related-assets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 10
  snyk-api-cli list-related-assets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --type repository
  snyk-api-cli list-related-assets 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose --include`,
	Args: cobra.ExactArgs(2),
	RunE: runListRelatedAssets,
}

var (
	// Query parameters
	listRelatedAssetsStartingAfter string
	listRelatedAssetsEndingBefore  string
	listRelatedAssetsLimit         int
	listRelatedAssetsType          string
	
	// Standard flags
	listRelatedAssetsVerbose       bool
	listRelatedAssetsSilent        bool
	listRelatedAssetsIncludeResp   bool
	listRelatedAssetsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListRelatedAssetsCmd.Flags().StringVar(&listRelatedAssetsStartingAfter, "starting-after", "", "Cursor for pagination, return records after this position")
	ListRelatedAssetsCmd.Flags().StringVar(&listRelatedAssetsEndingBefore, "ending-before", "", "Cursor for pagination, return records before this position")
	ListRelatedAssetsCmd.Flags().IntVar(&listRelatedAssetsLimit, "limit", 0, "Number of records to return")
	ListRelatedAssetsCmd.Flags().StringVar(&listRelatedAssetsType, "type", "", "Filter by asset type (repository, package, image)")
	
	// Add standard flags like other commands
	ListRelatedAssetsCmd.Flags().BoolVarP(&listRelatedAssetsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListRelatedAssetsCmd.Flags().BoolVarP(&listRelatedAssetsSilent, "silent", "s", false, "Silent mode")
	ListRelatedAssetsCmd.Flags().BoolVarP(&listRelatedAssetsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListRelatedAssetsCmd.Flags().StringVarP(&listRelatedAssetsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListRelatedAssets(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	assetID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListRelatedAssetsURL(endpoint, version, groupID, assetID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listRelatedAssetsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listRelatedAssetsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listRelatedAssetsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listRelatedAssetsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listRelatedAssetsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listRelatedAssetsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listRelatedAssetsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListRelatedAssetsResponse(resp, listRelatedAssetsIncludeResp, listRelatedAssetsVerbose, listRelatedAssetsSilent)
}

func buildListRelatedAssetsURL(endpoint, version, groupID, assetID string) (string, error) {
	// Build base URL with group ID and asset ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/assets/%s/relationships/assets", endpoint, groupID, assetID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()
	q.Set("version", version)
	
	if listRelatedAssetsStartingAfter != "" {
		q.Set("starting_after", listRelatedAssetsStartingAfter)
	}
	if listRelatedAssetsEndingBefore != "" {
		q.Set("ending_before", listRelatedAssetsEndingBefore)
	}
	if listRelatedAssetsLimit > 0 {
		q.Set("limit", strconv.Itoa(listRelatedAssetsLimit))
	}
	if listRelatedAssetsType != "" {
		q.Set("type", listRelatedAssetsType)
	}
	
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func handleListRelatedAssetsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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