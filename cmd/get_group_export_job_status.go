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

// GetGroupExportJobStatusCmd represents the get-group-export-job-status command
var GetGroupExportJobStatusCmd = &cobra.Command{
	Use:   "get-group-export-job-status [group_id] [export_id]",
	Short: "Get the status of a group export job from Snyk",
	Long: `Get the status of a group export job from the Snyk API.

This command retrieves the status of a specific group export job by its group ID and export ID.
Both the group ID and export ID must be provided as required arguments.

The response will include the job status which can be one of: PENDING, FINISHED, ERRORED, STARTED.

Examples:
  snyk-api-cli get-group-export-job-status 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli get-group-export-job-status 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli get-group-export-job-status 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetGroupExportJobStatus,
}

var (
	getGroupExportJobStatusVerbose     bool
	getGroupExportJobStatusSilent      bool
	getGroupExportJobStatusIncludeResp bool
	getGroupExportJobStatusUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetGroupExportJobStatusCmd.Flags().BoolVarP(&getGroupExportJobStatusVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetGroupExportJobStatusCmd.Flags().BoolVarP(&getGroupExportJobStatusSilent, "silent", "s", false, "Silent mode")
	GetGroupExportJobStatusCmd.Flags().BoolVarP(&getGroupExportJobStatusIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetGroupExportJobStatusCmd.Flags().StringVarP(&getGroupExportJobStatusUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetGroupExportJobStatus(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	exportID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetGroupExportJobStatusURL(endpoint, version, groupID, exportID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getGroupExportJobStatusVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getGroupExportJobStatusVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getGroupExportJobStatusVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getGroupExportJobStatusVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getGroupExportJobStatusVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getGroupExportJobStatusUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getGroupExportJobStatusVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetGroupExportJobStatusResponse(resp, getGroupExportJobStatusIncludeResp, getGroupExportJobStatusVerbose, getGroupExportJobStatusSilent)
}

func buildGetGroupExportJobStatusURL(endpoint, version, groupID, exportID string) (string, error) {
	// Build base URL with group ID and export ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/jobs/export/%s", endpoint, groupID, exportID)

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

func handleGetGroupExportJobStatusResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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