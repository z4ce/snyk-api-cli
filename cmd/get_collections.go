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

// GetCollectionsCmd represents the get-collections command
var GetCollectionsCmd = &cobra.Command{
	Use:   "get-collections [org_id]",
	Short: "Get collections from Snyk",
	Long: `Get collections from the Snyk API for a specific organization.

This command retrieves collections that can be used to organize and manage projects.
You can filter, sort, and paginate the results.

Examples:
  snyk-api-cli get-collections 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-collections 12345678-1234-5678-9012-123456789012 --sort name --direction ASC
  snyk-api-cli get-collections 12345678-1234-5678-9012-123456789012 --name "my-collection" --is-generated=false`,
	Args: cobra.ExactArgs(1),
	RunE: runGetCollections,
}

var (
	collectionsStartingAfter string
	collectionsEndingBefore  string
	collectionsLimit         int
	collectionsSort          string
	collectionsDirection     string
	collectionsName          string
	collectionsIsGenerated   string
	collectionsVerbose       bool
	collectionsSilent        bool
	collectionsIncludeResp   bool
	collectionsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetCollectionsCmd.Flags().StringVar(&collectionsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetCollectionsCmd.Flags().StringVar(&collectionsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	GetCollectionsCmd.Flags().IntVar(&collectionsLimit, "limit", 0, "Number of results to return per page")
	GetCollectionsCmd.Flags().StringVar(&collectionsSort, "sort", "", "Return collections sorted by the specified attributes (name, projectsCount, issues)")
	GetCollectionsCmd.Flags().StringVar(&collectionsDirection, "direction", "", "Return collections sorted in the specified direction (ASC, DESC)")
	GetCollectionsCmd.Flags().StringVar(&collectionsName, "name", "", "Return collections which names include the provided string")
	GetCollectionsCmd.Flags().StringVar(&collectionsIsGenerated, "is-generated", "", "Return collections where is_generated matches the provided boolean (true, false)")
	
	// Add standard flags like curl command
	GetCollectionsCmd.Flags().BoolVarP(&collectionsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetCollectionsCmd.Flags().BoolVarP(&collectionsSilent, "silent", "s", false, "Silent mode")
	GetCollectionsCmd.Flags().BoolVarP(&collectionsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetCollectionsCmd.Flags().StringVarP(&collectionsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetCollections(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetCollectionsURL(endpoint, orgID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if collectionsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if collectionsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if collectionsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if collectionsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if collectionsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", collectionsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if collectionsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleGetCollectionsResponse(resp, collectionsIncludeResp, collectionsVerbose, collectionsSilent)
}

func buildGetCollectionsURL(endpoint, orgID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/collections", endpoint, orgID)

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
	if collectionsStartingAfter != "" {
		q.Set("starting_after", collectionsStartingAfter)
	}
	if collectionsEndingBefore != "" {
		q.Set("ending_before", collectionsEndingBefore)
	}
	if collectionsLimit > 0 {
		q.Set("limit", strconv.Itoa(collectionsLimit))
	}
	if collectionsSort != "" {
		q.Set("sort", collectionsSort)
	}
	if collectionsDirection != "" {
		q.Set("direction", collectionsDirection)
	}
	if collectionsName != "" {
		q.Set("name", collectionsName)
	}
	if collectionsIsGenerated != "" {
		// Parse the string to validate it's a boolean
		if collectionsIsGenerated != "true" && collectionsIsGenerated != "false" {
			return "", fmt.Errorf("is-generated must be either 'true' or 'false', got: %s", collectionsIsGenerated)
		}
		q.Set("is_generated", collectionsIsGenerated)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetCollectionsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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