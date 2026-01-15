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

// ListOrgAssignmentsCmd represents the list-org-assignments command
var ListOrgAssignmentsCmd = &cobra.Command{
	Use:   "list-org-assignments [org_id]",
	Short: "Retrieve a list of assignments for an organization",
	Long: `Retrieve a list of assignments for an organization from the Snyk Learn API.

This command retrieves a list of learn assignments that have been created for users
within the specified organization. The results can be paginated using various
query parameters.

Examples:
  snyk-api-cli list-org-assignments 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-org-assignments 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-org-assignments 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli list-org-assignments 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli list-org-assignments 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListOrgAssignments,
}

var (
	listOrgAssignmentsLimit         int
	listOrgAssignmentsStartingAfter string
	listOrgAssignmentsEndingBefore  string
	listOrgAssignmentsVerbose       bool
	listOrgAssignmentsSilent        bool
	listOrgAssignmentsIncludeResp   bool
	listOrgAssignmentsUserAgent     string
)

func init() {
	// Add flags for query parameters
	ListOrgAssignmentsCmd.Flags().IntVar(&listOrgAssignmentsLimit, "limit", 0, "Number of results per page")
	ListOrgAssignmentsCmd.Flags().StringVar(&listOrgAssignmentsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListOrgAssignmentsCmd.Flags().StringVar(&listOrgAssignmentsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	ListOrgAssignmentsCmd.Flags().BoolVarP(&listOrgAssignmentsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgAssignmentsCmd.Flags().BoolVarP(&listOrgAssignmentsSilent, "silent", "s", false, "Silent mode")
	ListOrgAssignmentsCmd.Flags().BoolVarP(&listOrgAssignmentsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgAssignmentsCmd.Flags().StringVarP(&listOrgAssignmentsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgAssignments(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgAssignmentsURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listOrgAssignmentsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listOrgAssignmentsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Set user agent
	req.Header.Set("User-Agent", listOrgAssignmentsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListOrgAssignmentsResponse(resp, listOrgAssignmentsIncludeResp, listOrgAssignmentsVerbose, listOrgAssignmentsSilent)
}

func buildListOrgAssignmentsURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/learn/assignments", endpoint, orgID)

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
	if listOrgAssignmentsLimit > 0 {
		q.Set("limit", strconv.Itoa(listOrgAssignmentsLimit))
	}
	if listOrgAssignmentsStartingAfter != "" {
		q.Set("starting_after", listOrgAssignmentsStartingAfter)
	}
	if listOrgAssignmentsEndingBefore != "" {
		q.Set("ending_before", listOrgAssignmentsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListOrgAssignmentsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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