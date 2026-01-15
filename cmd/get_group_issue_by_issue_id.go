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

// GetGroupIssueByIssueIDCmd represents the get-group-issue-by-issue-id command
var GetGroupIssueByIssueIDCmd = &cobra.Command{
	Use:   "get-group-issue-by-issue-id [group_id] [issue_id]",
	Short: "Get a specific issue for a group by issue ID",
	Long: `Get a specific issue for a group by issue ID from the Snyk API.

This command retrieves detailed information about a specific issue within a group
by providing both the group ID and issue ID as required arguments.

The group ID and issue ID must be provided as UUIDs.

Examples:
  snyk-api-cli get-group-issue-by-issue-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-group-issue-by-issue-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-group-issue-by-issue-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetGroupIssueByIssueID,
}

var (
	getGroupIssueByIssueIDVerbose     bool
	getGroupIssueByIssueIDSilent      bool
	getGroupIssueByIssueIDIncludeResp bool
	getGroupIssueByIssueIDUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetGroupIssueByIssueIDCmd.Flags().BoolVarP(&getGroupIssueByIssueIDVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetGroupIssueByIssueIDCmd.Flags().BoolVarP(&getGroupIssueByIssueIDSilent, "silent", "s", false, "Silent mode")
	GetGroupIssueByIssueIDCmd.Flags().BoolVarP(&getGroupIssueByIssueIDIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetGroupIssueByIssueIDCmd.Flags().StringVarP(&getGroupIssueByIssueIDUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetGroupIssueByIssueID(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	issueID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetGroupIssueByIssueIDURL(endpoint, version, groupID, issueID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getGroupIssueByIssueIDVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getGroupIssueByIssueIDVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getGroupIssueByIssueIDVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getGroupIssueByIssueIDVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getGroupIssueByIssueIDVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getGroupIssueByIssueIDUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getGroupIssueByIssueIDVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetGroupIssueByIssueIDResponse(resp, getGroupIssueByIssueIDIncludeResp, getGroupIssueByIssueIDVerbose, getGroupIssueByIssueIDSilent)
}

func buildGetGroupIssueByIssueIDURL(endpoint, version, groupID, issueID string) (string, error) {
	// Build base URL with group ID and issue ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/issues/%s", endpoint, groupID, issueID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add query parameters
	q := u.Query()

	// Version is required
	q.Set("version", version)

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetGroupIssueByIssueIDResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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