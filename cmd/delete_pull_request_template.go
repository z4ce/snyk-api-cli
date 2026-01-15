package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeletePullRequestTemplateCmd represents the delete-pull-request-template command
var DeletePullRequestTemplateCmd = &cobra.Command{
	Use:   "delete-pull-request-template [group_id]",
	Short: "Delete a pull request template for a Snyk group",
	Long: `Delete a pull request template for a Snyk group from the Snyk API.

This command deletes the pull request template for a specific group using its unique identifier.
The group_id parameter is required and must be a valid UUID.

Examples:
  snyk-api-cli delete-pull-request-template 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-pull-request-template --verbose 12345678-1234-5678-9012-123456789012
  snyk-api-cli delete-pull-request-template --include 12345678-1234-5678-9012-123456789012`,
	Args: cobra.ExactArgs(1),
	RunE: runDeletePullRequestTemplate,
}

var (
	deletePullRequestTemplateVerbose     bool
	deletePullRequestTemplateSilent      bool
	deletePullRequestTemplateIncludeResp bool
	deletePullRequestTemplateUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeletePullRequestTemplateCmd.Flags().BoolVarP(&deletePullRequestTemplateVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeletePullRequestTemplateCmd.Flags().BoolVarP(&deletePullRequestTemplateSilent, "silent", "s", false, "Silent mode")
	DeletePullRequestTemplateCmd.Flags().BoolVarP(&deletePullRequestTemplateIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeletePullRequestTemplateCmd.Flags().StringVarP(&deletePullRequestTemplateUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeletePullRequestTemplate(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id path parameter
	fullURL, err := buildDeletePullRequestTemplateURL(endpoint, groupID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deletePullRequestTemplateVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deletePullRequestTemplateVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deletePullRequestTemplateVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deletePullRequestTemplateVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deletePullRequestTemplateVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deletePullRequestTemplateUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deletePullRequestTemplateVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleDeletePullRequestTemplateResponse(resp, deletePullRequestTemplateIncludeResp, deletePullRequestTemplateVerbose, deletePullRequestTemplateSilent)
}

func buildDeletePullRequestTemplateURL(endpoint, groupID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/settings/pull_request_template", endpoint, groupID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add required version query parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func handleDeletePullRequestTemplateResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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