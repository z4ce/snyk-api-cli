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

// ListChannelsCmd represents the list-channels command
var ListChannelsCmd = &cobra.Command{
	Use:   "list-channels [org_id] [tenant_id]",
	Short: "Get a list of Slack channels",
	Long: `Get a list of Slack channels from the Snyk API.

This command retrieves a list of available Slack channels for a specific organization
and tenant. Both organization ID and tenant ID must be provided.

Note: Currently only possible to page forwards through this collection.

Examples:
  snyk-api-cli list-channels 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli list-channels 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --limit 50
  snyk-api-cli list-channels 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --starting-after "cursor123" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runListChannels,
}

var (
	listChannelsStartingAfter string
	listChannelsEndingBefore  string
	listChannelsLimit         int
	listChannelsVerbose       bool
	listChannelsSilent        bool
	listChannelsIncludeResp   bool
	listChannelsUserAgent     string
)

func init() {
	// Add pagination flags
	ListChannelsCmd.Flags().StringVar(&listChannelsStartingAfter, "starting-after", "", "Cursor for pagination - results after this cursor")
	ListChannelsCmd.Flags().StringVar(&listChannelsEndingBefore, "ending-before", "", "Cursor for pagination - results before this cursor")
	ListChannelsCmd.Flags().IntVar(&listChannelsLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	ListChannelsCmd.Flags().BoolVarP(&listChannelsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListChannelsCmd.Flags().BoolVarP(&listChannelsSilent, "silent", "s", false, "Silent mode")
	ListChannelsCmd.Flags().BoolVarP(&listChannelsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListChannelsCmd.Flags().StringVarP(&listChannelsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListChannels(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	tenantID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListChannelsURL(endpoint, version, orgID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listChannelsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listChannelsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listChannelsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listChannelsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listChannelsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listChannelsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listChannelsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListChannelsResponse(resp, listChannelsIncludeResp, listChannelsVerbose, listChannelsSilent)
}

func buildListChannelsURL(endpoint, version, orgID, tenantID string) (string, error) {
	// Build base URL with org ID and tenant ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/slack_app/%s/channels", endpoint, orgID, tenantID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	// Add pagination parameters if specified
	if listChannelsStartingAfter != "" {
		q.Set("starting_after", listChannelsStartingAfter)
	}
	if listChannelsEndingBefore != "" {
		q.Set("ending_before", listChannelsEndingBefore)
	}
	if listChannelsLimit > 0 {
		q.Set("limit", strconv.Itoa(listChannelsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListChannelsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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