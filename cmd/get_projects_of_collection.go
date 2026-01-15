package cmd

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// GetProjectsOfCollectionCmd represents the get-projects-of-collection command
var GetProjectsOfCollectionCmd = &cobra.Command{
	Use:   "get-projects-of-collection [org_id] [collection_id]",
	Short: "Get projects of a collection from Snyk",
	Long: `Get projects that belong to a specific collection from the Snyk API.

This command retrieves projects associated with a collection within an organization.
You can filter, sort, and paginate the results using various query parameters.

Examples:
  snyk-api-cli get-projects-of-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987
  snyk-api-cli get-projects-of-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --sort imported --direction ASC
  snyk-api-cli get-projects-of-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --limit 10 --show vuln-groups`,
	Args: cobra.ExactArgs(2),
	RunE: runGetProjectsOfCollection,
}

var (
	projectsStartingAfter string
	projectsEndingBefore  string
	projectsLimit         int
	projectsSort          string
	projectsDirection     string
	projectsTargetIds     []string
	projectsShow          []string
	projectsIntegration   []string
	projectsVerbose       bool
	projectsSilent        bool
	projectsIncludeResp   bool
	projectsUserAgent     string
)

func init() {
	// Add flags for query parameters
	GetProjectsOfCollectionCmd.Flags().StringVar(&projectsStartingAfter, "starting-after", "", "Return the page of results immediately after this cursor")
	GetProjectsOfCollectionCmd.Flags().StringVar(&projectsEndingBefore, "ending-before", "", "Return the page of results immediately before this cursor")
	GetProjectsOfCollectionCmd.Flags().IntVar(&projectsLimit, "limit", 0, "Number of results to return per page")
	GetProjectsOfCollectionCmd.Flags().StringVar(&projectsSort, "sort", "", "Return projects sorted by the specified attribute (imported, last_tested_at, issues)")
	GetProjectsOfCollectionCmd.Flags().StringVar(&projectsDirection, "direction", "", "Return projects sorted in the specified direction (ASC, DESC)")
	GetProjectsOfCollectionCmd.Flags().StringSliceVar(&projectsTargetIds, "target-id", []string{}, "Return projects that belong to the provided targets (can be used multiple times)")
	GetProjectsOfCollectionCmd.Flags().StringSliceVar(&projectsShow, "show", []string{}, "Additional data to show (vuln-groups, clean-groups) (can be used multiple times)")
	GetProjectsOfCollectionCmd.Flags().StringSliceVar(&projectsIntegration, "integration", []string{}, "Filter by integration type (can be used multiple times)")
	
	// Add standard flags like curl command
	GetProjectsOfCollectionCmd.Flags().BoolVarP(&projectsVerbose, "verbose", "v", false, "Make the operation more talkative")
	GetProjectsOfCollectionCmd.Flags().BoolVarP(&projectsSilent, "silent", "s", false, "Silent mode")
	GetProjectsOfCollectionCmd.Flags().BoolVarP(&projectsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	GetProjectsOfCollectionCmd.Flags().StringVarP(&projectsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runGetProjectsOfCollection(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	collectionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with query parameters
	fullURL, err := buildGetProjectsOfCollectionURL(endpoint, orgID, collectionID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if projectsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting GET %s\n", fullURL)
	}

	// Create the HTTP request
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if projectsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if projectsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if projectsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if projectsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", projectsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if projectsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleGetProjectsOfCollectionResponse(resp, projectsIncludeResp, projectsVerbose, projectsSilent)
}

func buildGetProjectsOfCollectionURL(endpoint, orgID, collectionID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/collections/%s/relationships/projects", endpoint, orgID, collectionID)

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
	if projectsStartingAfter != "" {
		q.Set("starting_after", projectsStartingAfter)
	}
	if projectsEndingBefore != "" {
		q.Set("ending_before", projectsEndingBefore)
	}
	if projectsLimit > 0 {
		q.Set("limit", strconv.Itoa(projectsLimit))
	}
	if projectsSort != "" {
		// Validate sort parameter
		validSorts := []string{"imported", "last_tested_at", "issues"}
		if !containsString(validSorts, projectsSort) {
			return "", fmt.Errorf("invalid sort parameter: %s, must be one of: %s", projectsSort, strings.Join(validSorts, ", "))
		}
		q.Set("sort", projectsSort)
	}
	if projectsDirection != "" {
		// Validate direction parameter
		validDirections := []string{"ASC", "DESC"}
		if !containsString(validDirections, projectsDirection) {
			return "", fmt.Errorf("invalid direction parameter: %s, must be one of: %s", projectsDirection, strings.Join(validDirections, ", "))
		}
		q.Set("direction", projectsDirection)
	}
	
	// Handle array parameters
	if len(projectsTargetIds) > 0 {
		for _, targetID := range projectsTargetIds {
			q.Add("target_id", targetID)
		}
	}
	if len(projectsShow) > 0 {
		// Validate show parameters
		validShows := []string{"vuln-groups", "clean-groups"}
		for _, show := range projectsShow {
			if !containsString(validShows, show) {
				return "", fmt.Errorf("invalid show parameter: %s, must be one of: %s", show, strings.Join(validShows, ", "))
			}
		}
		for _, show := range projectsShow {
			q.Add("show", show)
		}
	}
	if len(projectsIntegration) > 0 {
		for _, integration := range projectsIntegration {
			q.Add("integration", integration)
		}
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func handleGetProjectsOfCollectionResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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

