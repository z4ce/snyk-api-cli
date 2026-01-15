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

// GetAppBotsCmd represents the get-app-bots command
var GetAppBotsCmd = &cobra.Command{
	Use:   "get-app-bots [org_id]",
	Short: "Get a list of app bots authorized to an organization",
	Long: `Get a list of app bots authorized to an organization from the Snyk API.

This command retrieves app bots that are authorized to the specified organization.
You can filter and paginate the results using the available flags.

Examples:
  snyk-api-cli get-app-bots 12345678-1234-5678-9012-123456789012
  snyk-api-cli get-app-bots 12345678-1234-5678-9012-123456789012 --expand app
  snyk-api-cli get-app-bots 12345678-1234-5678-9012-123456789012 --limit 10 --starting-after cursor123`,
	Args: cobra.ExactArgs(1),
	RunE: runGetAppBots,
}

var (
	getAppBotsExpand        []string
	getAppBotsStartingAfter string
	getAppBotsEndingBefore  string
	getAppBotsLimit         int
	getAppBotsVerbose       bool
	getAppBotsSilent        bool
	getAppBotsIncludeResp   bool
	getAppBotsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetAppBotsCmd.Flags().StringSliceVar(&getAppBotsExpand, "expand", []string{}, "Expand relationships (can be used multiple times)")
	GetAppBotsCmd.Flags().StringVar(&getAppBotsStartingAfter, "starting-after", "", "Pagination cursor for next page")
	GetAppBotsCmd.Flags().StringVar(&getAppBotsEndingBefore, "ending-before", "", "Pagination cursor for previous page")
	GetAppBotsCmd.Flags().IntVar(&getAppBotsLimit, "limit", 0, "Number of results per page")
	
	// Add standard flags like curl command
	GetAppBotsCmd.Flags().BoolVarP(&getAppBotsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetAppBotsCmd.Flags().BoolVarP(&getAppBotsSilent, "silent", "s", false, "Silent mode")
	GetAppBotsCmd.Flags().BoolVarP(&getAppBotsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetAppBotsCmd.Flags().StringVarP(&getAppBotsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetAppBots(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetAppBotsURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getAppBotsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getAppBotsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getAppBotsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getAppBotsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getAppBotsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getAppBotsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getAppBotsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleGetAppBotsResponse(resp, getAppBotsIncludeResp, getAppBotsVerbose, getAppBotsSilent)
}

func buildGetAppBotsURL(endpoint, version, orgID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/app_bots", endpoint, orgID)

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
	if len(getAppBotsExpand) > 0 {
		for _, expand := range getAppBotsExpand {
			q.Add("expand", expand)
		}
	}
	if getAppBotsStartingAfter != "" {
		q.Set("starting_after", getAppBotsStartingAfter)
	}
	if getAppBotsEndingBefore != "" {
		q.Set("ending_before", getAppBotsEndingBefore)
	}
	if getAppBotsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getAppBotsLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetAppBotsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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