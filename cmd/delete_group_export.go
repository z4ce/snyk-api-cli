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

// DeleteGroupExportCmd represents the delete-group-export command
var DeleteGroupExportCmd = &cobra.Command{
	Use:   "delete-group-export [group_id] [export_id]",
	Short: "Delete a group export by ID from Snyk",
	Long: `Delete a group export by ID from the Snyk API.

This command deletes a specific group export using its unique identifier.
Both group_id and export_id parameters are required and must be valid UUIDs.

Examples:
  snyk-api-cli delete-group-export 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-export --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-group-export --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteGroupExport,
}

var (
	deleteGroupExportVerbose     bool
	deleteGroupExportSilent      bool
	deleteGroupExportIncludeResp bool
	deleteGroupExportUserAgent   string
)

func init() {
	// Add standard flags like curl command
	DeleteGroupExportCmd.Flags().BoolVarP(&deleteGroupExportVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteGroupExportCmd.Flags().BoolVarP(&deleteGroupExportSilent, "silent", "s", false, "Silent mode")
	DeleteGroupExportCmd.Flags().BoolVarP(&deleteGroupExportIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteGroupExportCmd.Flags().StringVarP(&deleteGroupExportUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteGroupExport(cmd *cobra.Command, args []string) error {
	groupID := args[0]
	exportID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the group_id and export_id path parameters
	fullURL, err := buildDeleteGroupExportURL(endpoint, groupID, exportID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteGroupExportVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteGroupExportVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteGroupExportVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteGroupExportVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteGroupExportVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteGroupExportUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteGroupExportVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleDeleteGroupExportResponse(resp, deleteGroupExportIncludeResp, deleteGroupExportVerbose, deleteGroupExportSilent)
}

func buildDeleteGroupExportURL(endpoint, groupID, exportID, version string) (string, error) {
	// Validate the group_id parameter
	if strings.TrimSpace(groupID) == "" {
		return "", fmt.Errorf("group_id cannot be empty")
	}

	// Validate the export_id parameter
	if strings.TrimSpace(exportID) == "" {
		return "", fmt.Errorf("export_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/groups/%s/export/%s", endpoint, groupID, exportID)

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

func handleDeleteGroupExportResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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