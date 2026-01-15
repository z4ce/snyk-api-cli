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

// DeleteOrgProjectCmd represents the delete-org-project command
var DeleteOrgProjectCmd = &cobra.Command{
	Use:   "delete-org-project [org_id] [project_id]",
	Short: "Delete a project by ID from a Snyk organization",
	Long: `Delete a project by ID from a Snyk organization.

This command deletes a specific project using its unique identifier within an organization.
Both org_id and project_id parameters are required and must be valid UUIDs.

Required permissions: View Organization, View Projects, Remove Projects

Examples:
  snyk-api-cli delete-org-project 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli delete-org-project 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli delete-org-project 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteOrgProject,
}

var (
	deleteOrgProjectVerbose     bool
	deleteOrgProjectSilent      bool
	deleteOrgProjectIncludeResp bool
	deleteOrgProjectUserAgent   string
)

func init() {
	// Add standard flags like other commands
	DeleteOrgProjectCmd.Flags().BoolVarP(&deleteOrgProjectVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgProjectCmd.Flags().BoolVarP(&deleteOrgProjectSilent, "silent", "s", false, "Silent mode")
	DeleteOrgProjectCmd.Flags().BoolVarP(&deleteOrgProjectIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgProjectCmd.Flags().StringVarP(&deleteOrgProjectUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgProject(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	projectID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and project_id path parameters
	fullURL, err := buildDeleteOrgProjectURL(endpoint, orgID, projectID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteOrgProjectVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteOrgProjectVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteOrgProjectVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteOrgProjectVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteOrgProjectVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteOrgProjectUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteOrgProjectVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteOrgProjectResponse(resp, deleteOrgProjectIncludeResp, deleteOrgProjectVerbose, deleteOrgProjectSilent)
}

func buildDeleteOrgProjectURL(endpoint, orgID, projectID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the project_id parameter
	if strings.TrimSpace(projectID) == "" {
		return "", fmt.Errorf("project_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/projects/%s", endpoint, orgID, projectID)

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

func handleDeleteOrgProjectResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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