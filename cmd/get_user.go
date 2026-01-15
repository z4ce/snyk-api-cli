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

// GetUserCmd represents the get-user command
var GetUserCmd = &cobra.Command{
	Use:   "get-user [org_id] [id]",
	Short: "Get user by ID from Snyk",
	Long: `Get user by ID from the Snyk API.

This command retrieves detailed information about a specific user by their ID within an organization.
Both the organization ID and user ID must be provided as required arguments.

Required permissions: View users (org.user.read)

Examples:
  snyk-api-cli get-user 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-user 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli get-user 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetUser,
}

var (
	getUserVerbose     bool
	getUserSilent      bool
	getUserIncludeResp bool
	getUserUserAgent   string
)

func init() {
	// Add standard flags like other commands
	GetUserCmd.Flags().BoolVarP(&getUserVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetUserCmd.Flags().BoolVarP(&getUserSilent, "silent", "s", false, "Silent mode")
	GetUserCmd.Flags().BoolVarP(&getUserIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetUserCmd.Flags().StringVarP(&getUserUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetUser(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	userID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetUserURL(endpoint, version, orgID, userID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getUserVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getUserVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getUserVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getUserVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getUserVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getUserUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getUserVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetUserResponse(resp, getUserIncludeResp, getUserVerbose, getUserSilent)
}

func buildGetUserURL(endpoint, version, orgID, userID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(userID) == "" {
		return "", fmt.Errorf("user_id cannot be empty")
	}

	// Build base URL with organization ID and user ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/users/%s", endpoint, orgID, userID)

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

func handleGetUserResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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