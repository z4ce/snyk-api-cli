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

// ListAssetProjectsCmd represents the list-asset-projects command
var ListAssetProjectsCmd = &cobra.Command{
	Use:   "list-asset-projects [group_id] [asset_id]",
	Short: "List projects related to a specific asset from Snyk",
	Long: `List projects related to a specific asset from the Snyk API.

This command retrieves projects that are related to a specific asset by its ID within a group.
Both the group ID and asset ID must be provided as required arguments.

Required permissions: View Groups (group.read)

Examples:
  snyk-api-cli list-asset-projects 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321
  snyk-api-cli list-asset-projects 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321 --limit 10
  snyk-api-cli list-asset-projects 12345678-1234-1234-1234-123456789012 87654321-8765-4321-8765-210987654321 --starting-after cursor123 --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runListAssetProjects,
}

var (
	// Pagination parameters
	listAssetProjectsLimit         int
	listAssetProjectsStartingAfter string
	listAssetProjectsEndingBefore  string
	
	// Standard flags
	listAssetProjectsVerbose     bool
	listAssetProjectsSilent      bool
	listAssetProjectsIncludeResp bool
	listAssetProjectsUserAgent   string
)

func init() {
	// Add pagination flags
	ListAssetProjectsCmd.Flags().IntVar(&listAssetProjectsLimit, "limit", 0, "Number of results to return")
	ListAssetProjectsCmd.Flags().StringVar(&listAssetProjectsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListAssetProjectsCmd.Flags().StringVar(&listAssetProjectsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	
	// Add standard flags like other commands
	ListAssetProjectsCmd.Flags().BoolVarP(&listAssetProjectsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListAssetProjectsCmd.Flags().BoolVarP(&listAssetProjectsSilent, "silent", "s", false, "Silent mode")
	ListAssetProjectsCmd.Flags().BoolVarP(&listAssetProjectsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListAssetProjectsCmd.Flags().StringVarP(&listAssetProjectsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListAssetProjects(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	assetID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListAssetProjectsURL(endpoint, version, groupID, assetID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listAssetProjectsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listAssetProjectsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listAssetProjectsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listAssetProjectsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listAssetProjectsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listAssetProjectsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listAssetProjectsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListAssetProjectsResponse(resp, listAssetProjectsIncludeResp, listAssetProjectsVerbose, listAssetProjectsSilent)
}

func buildListAssetProjectsURL(endpoint, version, groupID, assetID string) (string, error) {
	// Build base URL with group ID and asset ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/assets/%s/relationships/projects", endpoint, groupID, assetID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add pagination parameters if provided
	if listAssetProjectsLimit > 0 {
		q.Set("limit", strconv.Itoa(listAssetProjectsLimit))
	}
	if listAssetProjectsStartingAfter != "" {
		q.Set("starting_after", listAssetProjectsStartingAfter)
	}
	if listAssetProjectsEndingBefore != "" {
		q.Set("ending_before", listAssetProjectsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListAssetProjectsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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