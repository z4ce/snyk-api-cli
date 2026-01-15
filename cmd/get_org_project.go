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

// GetOrgProjectCmd represents the get-org-project command
var GetOrgProjectCmd = &cobra.Command{
	Use:   "get-org-project [org_id] [project_id]",
	Short: "Get a project by ID from a Snyk organization",
	Long: `Get a project by ID from a Snyk organization.

This command retrieves detailed information about a specific project by its ID within an organization.
Both the organization ID and project ID must be provided as required arguments.

Required permissions: View Projects (org.project.read)

Examples:
  snyk-api-cli get-org-project 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-org-project 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --expand "target"
  snyk-api-cli get-org-project 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --meta-latest-issue-counts --meta-latest-dependency-total
  snyk-api-cli get-org-project 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --verbose
  snyk-api-cli get-org-project 12345678-1234-1234-1234-123456789012 87654321-4321-8765-2109-876543210987 --include`,
	Args: cobra.ExactArgs(2),
	RunE: runGetOrgProject,
}

var (
	getOrgProjectExpand                       []string
	getOrgProjectMetaLatestIssueCounts        bool
	getOrgProjectMetaLatestDependencyTotal    bool
	getOrgProjectVerbose                      bool
	getOrgProjectSilent                       bool
	getOrgProjectIncludeResp                  bool
	getOrgProjectUserAgent                    string
)

func init() {
	// Add flags for query parameters
	GetOrgProjectCmd.Flags().StringSliceVar(&getOrgProjectExpand, "expand", []string{}, "Expand relationships (e.g., 'target')")
	GetOrgProjectCmd.Flags().BoolVar(&getOrgProjectMetaLatestIssueCounts, "meta-latest-issue-counts", false, "Include latest issue count summary")
	GetOrgProjectCmd.Flags().BoolVar(&getOrgProjectMetaLatestDependencyTotal, "meta-latest-dependency-total", false, "Include total dependencies count")

	// Add standard flags like other commands
	GetOrgProjectCmd.Flags().BoolVarP(&getOrgProjectVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetOrgProjectCmd.Flags().BoolVarP(&getOrgProjectSilent, "silent", "s", false, "Silent mode")
	GetOrgProjectCmd.Flags().BoolVarP(&getOrgProjectIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetOrgProjectCmd.Flags().StringVarP(&getOrgProjectUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetOrgProject(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	projectID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildGetOrgProjectURL(endpoint, version, orgID, projectID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if getOrgProjectVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if getOrgProjectVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if getOrgProjectVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if getOrgProjectVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if getOrgProjectVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", getOrgProjectUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if getOrgProjectVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleGetOrgProjectResponse(resp, getOrgProjectIncludeResp, getOrgProjectVerbose, getOrgProjectSilent)
}

func buildGetOrgProjectURL(endpoint, version, orgID, projectID string) (string, error) {
	// Validate the required parameters
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}
	if strings.TrimSpace(projectID) == "" {
		return "", fmt.Errorf("project_id cannot be empty")
	}

	// Build base URL with organization ID and project ID path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/projects/%s", endpoint, orgID, projectID)

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
	if len(getOrgProjectExpand) > 0 {
		for _, expand := range getOrgProjectExpand {
			q.Add("expand", expand)
		}
	}
	if getOrgProjectMetaLatestIssueCounts {
		q.Set("meta.latest_issue_counts", "true")
	}
	if getOrgProjectMetaLatestDependencyTotal {
		q.Set("meta.latest_dependency_total", "true")
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetOrgProjectResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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