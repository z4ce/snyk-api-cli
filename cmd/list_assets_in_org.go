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

// ListAssetsInOrgCmd represents the list-assets-in-org command
var ListAssetsInOrgCmd = &cobra.Command{
	Use:   "list-assets-in-org [org_id]",
	Short: "List assets in a specific organization from Snyk",
	Long: `List assets in a specific organization from the Snyk API.

This command retrieves assets (repositories, images, packages) within a specific organization.
The organization ID must be provided as a required argument. Various query parameters can be
used to paginate and filter the results.

Examples:
  snyk-api-cli list-assets-in-org 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-assets-in-org 12345678-1234-1234-1234-123456789012 --limit 50
  snyk-api-cli list-assets-in-org 12345678-1234-1234-1234-123456789012 --starting-after cursor123
  snyk-api-cli list-assets-in-org 12345678-1234-1234-1234-123456789012 --filter-asset-type repository
  snyk-api-cli list-assets-in-org 12345678-1234-1234-1234-123456789012 --verbose --include`,
	Args: cobra.ExactArgs(1),
	RunE: runListAssetsInOrg,
}

var (
	// Query parameters
	listAssetsInOrgLimit         int
	listAssetsInOrgStartingAfter string
	listAssetsInOrgEndingBefore  string
	
	// Filter parameters
	listAssetsInOrgFilterAssetType string
	listAssetsInOrgFilterProjectID string
	listAssetsInOrgFilterTargetID  string
	
	// Standard flags
	listAssetsInOrgVerbose     bool
	listAssetsInOrgSilent      bool
	listAssetsInOrgIncludeResp bool
	listAssetsInOrgUserAgent   string
)

func init() {
	// Add query parameter flags
	ListAssetsInOrgCmd.Flags().IntVar(&listAssetsInOrgLimit, "limit", 0, "Number of results to return (up to 100)")
	ListAssetsInOrgCmd.Flags().StringVar(&listAssetsInOrgStartingAfter, "starting-after", "", "Return records after this cursor position")
	ListAssetsInOrgCmd.Flags().StringVar(&listAssetsInOrgEndingBefore, "ending-before", "", "Return records before this cursor position")
	
	// Add filter parameter flags
	ListAssetsInOrgCmd.Flags().StringVar(&listAssetsInOrgFilterAssetType, "filter-asset-type", "", "Filter by asset type (e.g., repository, package)")
	ListAssetsInOrgCmd.Flags().StringVar(&listAssetsInOrgFilterProjectID, "filter-project-id", "", "Filter by Snyk Project ID (UUID)")
	ListAssetsInOrgCmd.Flags().StringVar(&listAssetsInOrgFilterTargetID, "filter-target-id", "", "Filter by Snyk Target ID (UUID)")
	
	// Add standard flags like other commands
	ListAssetsInOrgCmd.Flags().BoolVarP(&listAssetsInOrgVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListAssetsInOrgCmd.Flags().BoolVarP(&listAssetsInOrgSilent, "silent", "s", false, "Silent mode")
	ListAssetsInOrgCmd.Flags().BoolVarP(&listAssetsInOrgIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListAssetsInOrgCmd.Flags().StringVarP(&listAssetsInOrgUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListAssetsInOrg(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListAssetsInOrgURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listAssetsInOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listAssetsInOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listAssetsInOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listAssetsInOrgVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listAssetsInOrgVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listAssetsInOrgUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listAssetsInOrgVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListAssetsInOrgResponse(resp, listAssetsInOrgIncludeResp, listAssetsInOrgVerbose, listAssetsInOrgSilent)
}

func buildListAssetsInOrgURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with org ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/assets", endpoint, orgID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()
	
	// Add version parameter (required)
	q.Set("version", version)
	
	// Add limit parameter if provided
	if listAssetsInOrgLimit > 0 {
		q.Set("limit", strconv.Itoa(listAssetsInOrgLimit))
	}
	
	// Add pagination parameters if provided
	if listAssetsInOrgStartingAfter != "" {
		q.Set("starting_after", listAssetsInOrgStartingAfter)
	}
	if listAssetsInOrgEndingBefore != "" {
		q.Set("ending_before", listAssetsInOrgEndingBefore)
	}
	
	// Add filter parameters if provided using bracket notation
	if listAssetsInOrgFilterAssetType != "" {
		q.Set("filter[asset_type]", listAssetsInOrgFilterAssetType)
	}
	if listAssetsInOrgFilterProjectID != "" {
		q.Set("filter[project_id]", listAssetsInOrgFilterProjectID)
	}
	if listAssetsInOrgFilterTargetID != "" {
		q.Set("filter[target_id]", listAssetsInOrgFilterTargetID)
	}
	
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func handleListAssetsInOrgResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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