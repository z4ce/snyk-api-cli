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

// DeleteAppByIDCmd represents the delete-app-by-id command
var DeleteAppByIDCmd = &cobra.Command{
	Use:   "delete-app-by-id [org_id] [app_id]",
	Short: "Delete a specific app by ID from an organization",
	Long: `Delete a specific app by ID from an organization in the Snyk API.

This command deletes a specific app within an organization by providing both the 
organization ID and app ID as required arguments.

The organization ID and app ID must be provided as UUIDs.

Examples:
  snyk-api-cli delete-app-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321
  snyk-api-cli delete-app-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --verbose
  snyk-api-cli delete-app-by-id 12345678-1234-1234-1234-123456789012 87654321-4321-4321-4321-210987654321 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteAppByID,
}

var (
	deleteAppByIDVerbose     bool
	deleteAppByIDSilent      bool
	deleteAppByIDIncludeResp bool
	deleteAppByIDUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteAppByIDCmd.Flags().BoolVarP(&deleteAppByIDVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteAppByIDCmd.Flags().BoolVarP(&deleteAppByIDSilent, "silent", "s", false, "Silent mode")
	DeleteAppByIDCmd.Flags().BoolVarP(&deleteAppByIDIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteAppByIDCmd.Flags().StringVarP(&deleteAppByIDUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteAppByID(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	appID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildDeleteAppByIDURL(endpoint, version, orgID, appID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteAppByIDVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteAppByIDVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteAppByIDVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteAppByIDVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteAppByIDVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteAppByIDUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteAppByIDVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteAppByIDResponse(resp, deleteAppByIDIncludeResp, deleteAppByIDVerbose, deleteAppByIDSilent)
}

func buildDeleteAppByIDURL(endpoint, version, orgID, appID string) (string, error) {
	// Build base URL with org ID and app ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/apps/creations/%s", endpoint, orgID, appID)

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

func handleDeleteAppByIDResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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
		// Only print response body if it's not empty (DELETE operations often return 204 No Content)
		if len(body) > 0 {
			fmt.Print(string(body))
		}
	}

	// Return error for non-2xx status codes if verbose
	if verbose && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}