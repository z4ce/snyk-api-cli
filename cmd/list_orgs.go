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

// ListOrgsCmd represents the list-orgs command
var ListOrgsCmd = &cobra.Command{
	Use:   "list-orgs",
	Short: "List organizations from Snyk",
	Long: `List organizations from the Snyk API.

This command retrieves a list of organizations that the authenticated user can access.
The results can be filtered and paginated using various query parameters.

Examples:
  snyk-api-cli list-orgs
  snyk-api-cli list-orgs --limit 10
  snyk-api-cli list-orgs --group-id 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-orgs --is-personal true
  snyk-api-cli list-orgs --slug my-org
  snyk-api-cli list-orgs --name "My Organization"
  snyk-api-cli list-orgs --expand member_role
  snyk-api-cli list-orgs --starting-after abc123
  snyk-api-cli list-orgs --ending-before xyz789
  snyk-api-cli list-orgs --verbose`,
	RunE: runListOrgs,
}

var (
	listOrgsGroupID        string
	listOrgsIsPersonal     bool
	listOrgsSlug           string
	listOrgsName           string
	listOrgsExpand         []string
	listOrgsStartingAfter  string
	listOrgsEndingBefore   string
	listOrgsLimit          int
	listOrgsVerbose        bool
	listOrgsSilent         bool
	listOrgsIncludeResp    bool
	listOrgsUserAgent      string
)

func init() {
	// Add flags for query parameters
	ListOrgsCmd.Flags().StringVar(&listOrgsGroupID, "group-id", "", "Filter organizations within a specific group (UUID)")
	ListOrgsCmd.Flags().BoolVar(&listOrgsIsPersonal, "is-personal", false, "If true, returns only independent organizations")
	ListOrgsCmd.Flags().StringVar(&listOrgsSlug, "slug", "", "Returns orgs with exact matching slug")
	ListOrgsCmd.Flags().StringVar(&listOrgsName, "name", "", "Returns orgs whose name contains this value")
	ListOrgsCmd.Flags().StringSliceVar(&listOrgsExpand, "expand", []string{}, "Expand related resources like member_role (can be used multiple times)")
	ListOrgsCmd.Flags().StringVar(&listOrgsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListOrgsCmd.Flags().StringVar(&listOrgsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	ListOrgsCmd.Flags().IntVar(&listOrgsLimit, "limit", 0, "Number of results per page")

	// Add standard flags like other commands
	ListOrgsCmd.Flags().BoolVarP(&listOrgsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgsCmd.Flags().BoolVarP(&listOrgsSilent, "silent", "s", false, "Silent mode")
	ListOrgsCmd.Flags().BoolVarP(&listOrgsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgsCmd.Flags().StringVarP(&listOrgsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgs(cmd *cobra.Command, args []string) error {
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgsURL(endpoint, version, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listOrgsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listOrgsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listOrgsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listOrgsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listOrgsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listOrgsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listOrgsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListOrgsResponse(resp, listOrgsIncludeResp, listOrgsVerbose, listOrgsSilent)
}

func buildListOrgsURL(endpoint, version string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs", endpoint)

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
	if listOrgsGroupID != "" {
		q.Set("group_id", listOrgsGroupID)
	}
	if cmd.Flags().Changed("is-personal") {
		q.Set("is_personal", strconv.FormatBool(listOrgsIsPersonal))
	}
	if listOrgsSlug != "" {
		q.Set("slug", listOrgsSlug)
	}
	if listOrgsName != "" {
		q.Set("name", listOrgsName)
	}
	if len(listOrgsExpand) > 0 {
		// Handle expand as an array parameter
		for _, expand := range listOrgsExpand {
			q.Add("expand", expand)
		}
	}
	if listOrgsStartingAfter != "" {
		q.Set("starting_after", listOrgsStartingAfter)
	}
	if listOrgsEndingBefore != "" {
		q.Set("ending_before", listOrgsEndingBefore)
	}
	if listOrgsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listOrgsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListOrgsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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