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

// GetPullRequestTemplateCmd represents the get-pull-request-template command
var GetPullRequestTemplateCmd = &cobra.Command{
	Use:   "get-pull-request-template [group_id]",
	Short: "Get your groups pull request template",
	Long: `Get your groups pull request template from the Snyk API.

This command retrieves the pull request template for a specific group by its ID.
The group ID must be provided as a required argument.

Examples:
  snyk-api-cli get-pull-request-template 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-pull-request-template 12345678-1234-1234-1234-123456789012 --verbose
  snyk-api-cli get-pull-request-template 12345678-1234-1234-1234-123456789012 --include`,
	Args: cobra.ExactArgs(1),
	RunE: runGetPullRequestTemplate,
}

var (
	getPullRequestTemplateVerbose     bool
	getPullRequestTemplateSilent      bool
	getPullRequestTemplateIncludeResp bool
	getPullRequestTemplateUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetPullRequestTemplateCmd.Flags().BoolVarP(&getPullRequestTemplateVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetPullRequestTemplateCmd.Flags().BoolVarP(&getPullRequestTemplateSilent, "silent", "s", false, "Silent mode")
	GetPullRequestTemplateCmd.Flags().BoolVarP(&getPullRequestTemplateIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetPullRequestTemplateCmd.Flags().StringVarP(&getPullRequestTemplateUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetPullRequestTemplate(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetPullRequestTemplateURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getPullRequestTemplateVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getPullRequestTemplateVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getPullRequestTemplateVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getPullRequestTemplateVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getPullRequestTemplateVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getPullRequestTemplateUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getPullRequestTemplateVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetPullRequestTemplateResponse(resp, getPullRequestTemplateIncludeResp, getPullRequestTemplateVerbose, getPullRequestTemplateSilent)
}

func buildGetPullRequestTemplateURL(endpoint, version, groupID string) (string, error) {
	// Build base URL with group ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/settings/pull_request_template", endpoint, groupID)

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

func handleGetPullRequestTemplateResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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