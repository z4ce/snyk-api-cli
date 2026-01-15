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

// ListTenantLearningProgramsCmd represents the list-tenant-learning-programs command
var ListTenantLearningProgramsCmd = &cobra.Command{
	Use:   "list-tenant-learning-programs [tenant_id]",
	Short: "List learning programs for a tenant from Snyk",
	Long: `List learning programs for a tenant from the Snyk API.

This command retrieves a list of learning programs for a specific tenant.
The tenant ID must be provided as a required argument.

Examples:
  snyk-api-cli list-tenant-learning-programs 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-tenant-learning-programs 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-tenant-learning-programs 12345678-1234-1234-1234-123456789012 --starting-after abc123
  snyk-api-cli list-tenant-learning-programs 12345678-1234-1234-1234-123456789012 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListTenantLearningPrograms,
}

var (
	listTenantLearningProgramsVerbose       bool
	listTenantLearningProgramsSilent        bool
	listTenantLearningProgramsIncludeResp   bool
	listTenantLearningProgramsUserAgent     string
	listTenantLearningProgramsStartingAfter string
	listTenantLearningProgramsEndingBefore  string
	listTenantLearningProgramsLimit         int
)

func init() {
	// Add standard flags like other commands
	ListTenantLearningProgramsCmd.Flags().BoolVarP(&listTenantLearningProgramsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListTenantLearningProgramsCmd.Flags().BoolVarP(&listTenantLearningProgramsSilent, "silent", "s", false, "Silent mode")
	ListTenantLearningProgramsCmd.Flags().BoolVarP(&listTenantLearningProgramsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListTenantLearningProgramsCmd.Flags().StringVarP(&listTenantLearningProgramsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
	
	// Add pagination flags based on API spec
	ListTenantLearningProgramsCmd.Flags().StringVar(&listTenantLearningProgramsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after specified point")
	ListTenantLearningProgramsCmd.Flags().StringVar(&listTenantLearningProgramsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before specified point")
	ListTenantLearningProgramsCmd.Flags().IntVar(&listTenantLearningProgramsLimit, "limit", 0, "Number of results per page")
}

func runListTenantLearningPrograms(cmd *cobra.Command, args []string) error {
	tenantID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildListTenantLearningProgramsURL(endpoint, version, tenantID, listTenantLearningProgramsStartingAfter, listTenantLearningProgramsEndingBefore, listTenantLearningProgramsLimit)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listTenantLearningProgramsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listTenantLearningProgramsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listTenantLearningProgramsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listTenantLearningProgramsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listTenantLearningProgramsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listTenantLearningProgramsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listTenantLearningProgramsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListTenantLearningProgramsResponse(resp, listTenantLearningProgramsIncludeResp, listTenantLearningProgramsVerbose, listTenantLearningProgramsSilent)
}

func buildListTenantLearningProgramsURL(endpoint, version, tenantID, startingAfter, endingBefore string, limit int) (string, error) {
	// Build base URL with tenant ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/tenants/%s/learn/learning_programs", endpoint, tenantID)

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
	if startingAfter != "" {
		q.Set("starting_after", startingAfter)
	}
	if endingBefore != "" {
		q.Set("ending_before", endingBefore)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListTenantLearningProgramsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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