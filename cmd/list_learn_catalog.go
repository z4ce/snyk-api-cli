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

// ListLearnCatalogCmd represents the list-learn-catalog command
var ListLearnCatalogCmd = &cobra.Command{
	Use:   "list-learn-catalog",
	Short: "List learn catalog from Snyk",
	Long: `List learn catalog resources from the Snyk API.

This command retrieves a list of educational resources from the Snyk Learn catalog.
The results can be filtered by content source and paginated using cursor-based pagination.

Examples:
  snyk-api-cli list-learn-catalog
  snyk-api-cli list-learn-catalog --limit 10
  snyk-api-cli list-learn-catalog --content-source source-preview
  snyk-api-cli list-learn-catalog --starting-after abc123
  snyk-api-cli list-learn-catalog --ending-before xyz789
  snyk-api-cli list-learn-catalog --verbose`,
	RunE: runListLearnCatalog,
}

var (
	listLearnCatalogContentSource   string
	listLearnCatalogLimit           int
	listLearnCatalogStartingAfter   string
	listLearnCatalogEndingBefore    string
	listLearnCatalogVerbose         bool
	listLearnCatalogSilent          bool
	listLearnCatalogIncludeResp     bool
	listLearnCatalogUserAgent       string
)

func init() {
	// Add flags for query parameters
	ListLearnCatalogCmd.Flags().StringVar(&listLearnCatalogContentSource, "content-source", "", "Source of educational resources (source-preview, cache)")
	ListLearnCatalogCmd.Flags().IntVar(&listLearnCatalogLimit, "limit", 0, "Number of results per page")
	ListLearnCatalogCmd.Flags().StringVar(&listLearnCatalogStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListLearnCatalogCmd.Flags().StringVar(&listLearnCatalogEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like curl command
	ListLearnCatalogCmd.Flags().BoolVarP(&listLearnCatalogVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListLearnCatalogCmd.Flags().BoolVarP(&listLearnCatalogSilent, "silent", "s", false, "Silent mode")
	ListLearnCatalogCmd.Flags().BoolVarP(&listLearnCatalogIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListLearnCatalogCmd.Flags().StringVarP(&listLearnCatalogUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListLearnCatalog(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListLearnCatalogURL(endpoint, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listLearnCatalogVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listLearnCatalogVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listLearnCatalogVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listLearnCatalogVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listLearnCatalogVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listLearnCatalogUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listLearnCatalogVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListLearnCatalogResponse(resp, listLearnCatalogIncludeResp, listLearnCatalogVerbose, listLearnCatalogSilent)
}

func buildListLearnCatalogURL(endpoint, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/learn/catalog", endpoint)

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
	if listLearnCatalogContentSource != "" {
		q.Set("content_source", listLearnCatalogContentSource)
	}
	if listLearnCatalogLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listLearnCatalogLimit))
	}
	if listLearnCatalogStartingAfter != "" {
		q.Set("starting_after", listLearnCatalogStartingAfter)
	}
	if listLearnCatalogEndingBefore != "" {
		q.Set("ending_before", listLearnCatalogEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListLearnCatalogResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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