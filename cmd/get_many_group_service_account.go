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

// GetManyGroupServiceAccountCmd represents the get-many-group-service-account command
var GetManyGroupServiceAccountCmd = &cobra.Command{
	Use:   "get-many-group-service-account <group_id>",
	Short: "Get service accounts for a group",
	Long: `Get service accounts for a group from the Snyk API.

This command retrieves a list of service accounts for a specific group.
The results can be paginated using cursor-based pagination.

Examples:
  snyk-api-cli get-many-group-service-account 12345678-1234-1234-1234-123456789012
  snyk-api-cli get-many-group-service-account 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli get-many-group-service-account 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli get-many-group-service-account 12345678-1234-1234-1234-123456789012 --ending-before xyz789
  snyk-api-cli get-many-group-service-account 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runGetManyGroupServiceAccount,
}

var (
	getManyGroupServiceAccountStartingAfter string
	getManyGroupServiceAccountEndingBefore  string
	getManyGroupServiceAccountLimit         int
	getManyGroupServiceAccountVerbose       bool
	getManyGroupServiceAccountSilent        bool
	getManyGroupServiceAccountIncludeResp   bool
	getManyGroupServiceAccountUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetManyGroupServiceAccountCmd.Flags().StringVar(&getManyGroupServiceAccountStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	GetManyGroupServiceAccountCmd.Flags().StringVar(&getManyGroupServiceAccountEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")
	GetManyGroupServiceAccountCmd.Flags().IntVar(&getManyGroupServiceAccountLimit, "limit", 0, "Number of results per page")

	// Add standard flags like curl command
	GetManyGroupServiceAccountCmd.Flags().BoolVarP(&getManyGroupServiceAccountVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetManyGroupServiceAccountCmd.Flags().BoolVarP(&getManyGroupServiceAccountSilent, "silent", "s", false, "Silent mode")
	GetManyGroupServiceAccountCmd.Flags().BoolVarP(&getManyGroupServiceAccountIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetManyGroupServiceAccountCmd.Flags().StringVarP(&getManyGroupServiceAccountUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetManyGroupServiceAccount(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetManyGroupServiceAccountURL(endpoint, version, groupID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getManyGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getManyGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getManyGroupServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getManyGroupServiceAccountVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getManyGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getManyGroupServiceAccountUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getManyGroupServiceAccountVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetManyGroupServiceAccountResponse(resp, getManyGroupServiceAccountIncludeResp, getManyGroupServiceAccountVerbose, getManyGroupServiceAccountSilent)
}

func buildGetManyGroupServiceAccountURL(endpoint, version, groupID string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/service_accounts", endpoint, groupID)

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
	if getManyGroupServiceAccountStartingAfter != "" {
		q.Set("starting_after", getManyGroupServiceAccountStartingAfter)
	}
	if getManyGroupServiceAccountEndingBefore != "" {
		q.Set("ending_before", getManyGroupServiceAccountEndingBefore)
	}
	if getManyGroupServiceAccountLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", getManyGroupServiceAccountLimit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetManyGroupServiceAccountResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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