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

// ListOrgProjectsCmd represents the list-org-projects command
var ListOrgProjectsCmd = &cobra.Command{
	Use:   "list-org-projects [org_id]",
	Short: "List all projects for an organization from Snyk",
	Long: `List all projects for an organization from the Snyk API.

This command retrieves a list of projects that the authenticated user can access
within the specified organization. The results can be filtered and paginated using various
query parameters.

Required permissions: View Projects (org.project.read)

Examples:
  snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012
  snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012 --limit 10
  snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012 --names "project1,project2"
  snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012 --origins "github,gitlab"
  snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012 --types "npm,maven"
  snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012 --business-criticality "high,critical"
  snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012 --environment "production,staging"
  snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012 --lifecycle "development,production"
  snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012 --target-ids "target1,target2"
  snyk-api-cli list-org-projects 12345678-1234-1234-1234-123456789012 --starting-after "abc123" --limit 50 --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runListOrgProjects,
}

var (
	listOrgProjectsTargetIDs          []string
	listOrgProjectsNames              []string
	listOrgProjectsOrigins            []string
	listOrgProjectsTypes              []string
	listOrgProjectsBusinessCriticality []string
	listOrgProjectsEnvironment        []string
	listOrgProjectsLifecycle          []string
	listOrgProjectsLimit              int
	listOrgProjectsStartingAfter      string
	listOrgProjectsEndingBefore       string
	listOrgProjectsVerbose            bool
	listOrgProjectsSilent             bool
	listOrgProjectsIncludeResp        bool
	listOrgProjectsUserAgent          string
)

func init() {
	// Add flags for query parameters
	ListOrgProjectsCmd.Flags().StringSliceVar(&listOrgProjectsTargetIDs, "target-ids", []string{}, "Comma-separated list of target IDs to filter by")
	ListOrgProjectsCmd.Flags().StringSliceVar(&listOrgProjectsNames, "names", []string{}, "Comma-separated list of project names to filter by")
	ListOrgProjectsCmd.Flags().StringSliceVar(&listOrgProjectsOrigins, "origins", []string{}, "Comma-separated list of project origins to filter by")
	ListOrgProjectsCmd.Flags().StringSliceVar(&listOrgProjectsTypes, "types", []string{}, "Comma-separated list of project types to filter by")
	ListOrgProjectsCmd.Flags().StringSliceVar(&listOrgProjectsBusinessCriticality, "business-criticality", []string{}, "Comma-separated list of business criticality levels")
	ListOrgProjectsCmd.Flags().StringSliceVar(&listOrgProjectsEnvironment, "environment", []string{}, "Comma-separated list of environment types")
	ListOrgProjectsCmd.Flags().StringSliceVar(&listOrgProjectsLifecycle, "lifecycle", []string{}, "Comma-separated list of lifecycle stages")
	ListOrgProjectsCmd.Flags().IntVar(&listOrgProjectsLimit, "limit", 0, "Number of results per page")
	ListOrgProjectsCmd.Flags().StringVar(&listOrgProjectsStartingAfter, "starting-after", "", "Cursor for pagination, returns results after this point")
	ListOrgProjectsCmd.Flags().StringVar(&listOrgProjectsEndingBefore, "ending-before", "", "Cursor for pagination, returns results before this point")

	// Add standard flags like other commands
	ListOrgProjectsCmd.Flags().BoolVarP(&listOrgProjectsVerbose, "verbose", "v", false, "Make the operation more talkative")
	ListOrgProjectsCmd.Flags().BoolVarP(&listOrgProjectsSilent, "silent", "s", false, "Silent mode")
	ListOrgProjectsCmd.Flags().BoolVarP(&listOrgProjectsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	ListOrgProjectsCmd.Flags().StringVarP(&listOrgProjectsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runListOrgProjects(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildListOrgProjectsURL(endpoint, version, orgID, cmd)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if listOrgProjectsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if listOrgProjectsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if listOrgProjectsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if listOrgProjectsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if listOrgProjectsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", listOrgProjectsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if listOrgProjectsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleListOrgProjectsResponse(resp, listOrgProjectsIncludeResp, listOrgProjectsVerbose, listOrgProjectsSilent)
}

func buildListOrgProjectsURL(endpoint, version, orgID string, cmd *cobra.Command) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/projects", endpoint, orgID)

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
	if len(listOrgProjectsTargetIDs) > 0 {
		for _, targetID := range listOrgProjectsTargetIDs {
			q.Add("target_id", targetID)
		}
	}
	if len(listOrgProjectsNames) > 0 {
		for _, name := range listOrgProjectsNames {
			q.Add("names", name)
		}
	}
	if len(listOrgProjectsOrigins) > 0 {
		for _, origin := range listOrgProjectsOrigins {
			q.Add("origins", origin)
		}
	}
	if len(listOrgProjectsTypes) > 0 {
		for _, projectType := range listOrgProjectsTypes {
			q.Add("types", projectType)
		}
	}
	if len(listOrgProjectsBusinessCriticality) > 0 {
		for _, criticality := range listOrgProjectsBusinessCriticality {
			q.Add("business_criticality", criticality)
		}
	}
	if len(listOrgProjectsEnvironment) > 0 {
		for _, env := range listOrgProjectsEnvironment {
			q.Add("environment", env)
		}
	}
	if len(listOrgProjectsLifecycle) > 0 {
		for _, lifecycle := range listOrgProjectsLifecycle {
			q.Add("lifecycle", lifecycle)
		}
	}
	if listOrgProjectsLimit > 0 {
		q.Set("limit", fmt.Sprintf("%d", listOrgProjectsLimit))
	}
	if listOrgProjectsStartingAfter != "" {
		q.Set("starting_after", listOrgProjectsStartingAfter)
	}
	if listOrgProjectsEndingBefore != "" {
		q.Set("ending_before", listOrgProjectsEndingBefore)
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleListOrgProjectsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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