package cmd

import (
	"encoding/json"
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

// UpdateCollectionWithProjectsCmd represents the update-collection-with-projects command
var UpdateCollectionWithProjectsCmd = &cobra.Command{
	Use:   "update-collection-with-projects [org_id] [collection_id]",
	Short: "Update a collection with projects in a Snyk organization",
	Long: `Update a collection with projects in a Snyk organization.

This command updates a collection with projects in the specified organization using the Snyk API.
The org_id and collection_id parameters are required and should be valid UUIDs.

Examples:
  snyk-api-cli update-collection-with-projects 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-210987654321 --project-id "project-uuid-1"
  snyk-api-cli update-collection-with-projects 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-210987654321 --project-id "project-uuid-1" --project-id "project-uuid-2"`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateCollectionWithProjects,
}

var (
	updateCollectionProjectIds  []string
	updateCollectionVerbose     bool
	updateCollectionSilent      bool
	updateCollectionIncludeResp bool
	updateCollectionUserAgent   string
)

func init() {
	// Add flags for request body attributes
	UpdateCollectionWithProjectsCmd.Flags().StringArrayVar(&updateCollectionProjectIds, "project-id", []string{}, "Project ID (UUID) to add to collection (can be used multiple times)")

	// Add standard flags like curl command
	UpdateCollectionWithProjectsCmd.Flags().BoolVarP(&updateCollectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateCollectionWithProjectsCmd.Flags().BoolVarP(&updateCollectionSilent, "silent", "s", false, "Silent mode")
	UpdateCollectionWithProjectsCmd.Flags().BoolVarP(&updateCollectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateCollectionWithProjectsCmd.Flags().StringVarP(&updateCollectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Mark required flags
	UpdateCollectionWithProjectsCmd.MarkFlagRequired("project-id")
}

func runUpdateCollectionWithProjects(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	collectionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateCollectionWithProjectsURL(endpoint, orgID, collectionID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting POST %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateCollectionWithProjectsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateCollectionVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateCollectionVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateCollectionUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateCollectionVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as curl
	return handleUpdateCollectionWithProjectsResponse(resp, updateCollectionIncludeResp, updateCollectionVerbose, updateCollectionSilent)
}

func buildUpdateCollectionWithProjectsURL(endpoint, orgID, collectionID, version string) (string, error) {
	// Build base URL
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/collections/%s/relationships/projects", endpoint, orgID, collectionID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add version parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func buildUpdateCollectionWithProjectsRequestBody() (string, error) {
	// Build JSON:API format request body
	var dataArray []map[string]interface{}

	// Add each project ID as a data item
	for _, projectID := range updateCollectionProjectIds {
		dataItem := map[string]interface{}{
			"id":   projectID,
			"type": "project",
		}
		dataArray = append(dataArray, dataItem)
	}

	requestData := map[string]interface{}{
		"data": dataArray,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleUpdateCollectionWithProjectsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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
