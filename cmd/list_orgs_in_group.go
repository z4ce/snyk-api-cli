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

// ListOrgsInGroupCmd represents the list-orgs-in-group command
var ListOrgsInGroupCmd = &cobra.Command{
	Use:   "list-orgs-in-group [group_id]",
	Short: "List organizations in a group",
	Long: `List organizations in a group from the Snyk API.

This command retrieves a list of organizations that belong to a specific group.
The group_id parameter is required and must be a valid UUID.

Examples:
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012 --name "my org"
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012 --slug "my-org-slug"
  snyk-api-cli list-orgs-in-group 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListOrgsInGroup,
}

var (
	listOrgsInGroupStartingAfter string
	listOrgsInGroupEndingBefore  string
	listOrgsInGroupLimit         int
	listOrgsInGroupName          string
	listOrgsInGroupSlug          string
	listOrgsInGroupVerbose       bool
	listOrgsInGroupSilent        bool
	listOrgsInGroupIncludeResp   bool
	listOrgsInGroupUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListOrgsInGroupCmd.Flags().StringVar(&listOrgsInGroupStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	ListOrgsInGroupCmd.Flags().StringVar(&listOrgsInGroupEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	ListOrgsInGroupCmd.Flags().IntVar(&listOrgsInGroupLimit, "limit", 0, "Number of results to return per page")
	ListOrgsInGroupCmd.Flags().StringVar(&listOrgsInGroupName, "name", "", "Only return organizations whose name contains this value. Case insensitive.")
	ListOrgsInGroupCmd.Flags().StringVar(&listOrgsInGroupSlug, "slug", "", "Only return organizations whose slug exactly matches this value. Case sensitive.")

	// Add standard flags like curl command
	ListOrgsInGroupCmd.Flags().BoolVarP(&listOrgsInGroupVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgsInGroupCmd.Flags().BoolVarP(&listOrgsInGroupSilent, "silent", "s", false, "Silent mode")
	ListOrgsInGroupCmd.Flags().BoolVarP(&listOrgsInGroupIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgsInGroupCmd.Flags().StringVarP(&listOrgsInGroupUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgsInGroup(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgsInGroupURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listOrgsInGroupVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listOrgsInGroupVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listOrgsInGroupVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listOrgsInGroupVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listOrgsInGroupVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listOrgsInGroupUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listOrgsInGroupVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListOrgsInGroupResponse(resp, listOrgsInGroupIncludeResp, listOrgsInGroupVerbose, listOrgsInGroupSilent)
}

func buildListOrgsInGroupURL(endpoint, version, groupID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/orgs", endpoint, groupID)

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
	if listOrgsInGroupStartingAfter != "" {
		q.Set("starting_after", listOrgsInGroupStartingAfter)
	}
	if listOrgsInGroupEndingBefore != "" {
		q.Set("ending_before", listOrgsInGroupEndingBefore)
	}
	if listOrgsInGroupLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listOrgsInGroupLimit))
	}
	if listOrgsInGroupName != "" {
		q.Set("name", listOrgsInGroupName)
	}
	if listOrgsInGroupSlug != "" {
		q.Set("slug", listOrgsInGroupSlug)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListOrgsInGroupResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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