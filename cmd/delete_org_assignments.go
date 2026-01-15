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

// DeleteOrgAssignmentsCmd represents the delete-org-assignments command
var DeleteOrgAssignmentsCmd = &cobra.Command{
	Use:   "delete-org-assignments [org_id]",
	Short: "Bulk deletion of assignments in an organization",
	Long: `Bulk deletion of assignments in an organization using the Snyk Learn API.

This command allows bulk deletion of assignments within the specified organization.
You must provide either the assignment data as JSON using the --data flag, or specify
the assignment IDs using the available flags.

Examples:
  snyk-api-cli delete-org-assignments 12345678-1234-1234-1234-123456789012 --data '[{"id":"assign1","type":"lesson_assignment"},{"id":"assign2","type":"lesson_assignment"}]'
  snyk-api-cli delete-org-assignments 12345678-1234-1234-1234-123456789012 --assignment-ids "assign1,assign2"
  snyk-api-cli delete-org-assignments 12345678-1234-1234-1234-123456789012 --assignment-ids "assign1" --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runDeleteOrgAssignments,
}

var (
	deleteOrgAssignmentsData          string
	deleteOrgAssignmentsAssignmentIDs []string
	deleteOrgAssignmentsVerbose       bool
	deleteOrgAssignmentsSilent        bool
	deleteOrgAssignmentsIncludeResp   bool
	deleteOrgAssignmentsUserAgent     string
)

func init() {
	// Add flags for request body attributes
	DeleteOrgAssignmentsCmd.Flags().StringVar(&deleteOrgAssignmentsData, "data", "", "JSON data for the request body (if provided, other flags are ignored)")
	DeleteOrgAssignmentsCmd.Flags().StringSliceVar(&deleteOrgAssignmentsAssignmentIDs, "assignment-ids", []string{}, "Comma-separated list of assignment IDs to delete (required)")

	// Add standard flags like other commands
	DeleteOrgAssignmentsCmd.Flags().BoolVarP(&deleteOrgAssignmentsVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteOrgAssignmentsCmd.Flags().BoolVarP(&deleteOrgAssignmentsSilent, "silent", "s", false, "Silent mode")
	DeleteOrgAssignmentsCmd.Flags().BoolVarP(&deleteOrgAssignmentsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteOrgAssignmentsCmd.Flags().StringVarP(&deleteOrgAssignmentsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runDeleteOrgAssignments(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildDeleteOrgAssignmentsURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if deleteOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting DELETE %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildDeleteOrgAssignmentsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if deleteOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("DELETE", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if deleteOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if deleteOrgAssignmentsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if deleteOrgAssignmentsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if deleteOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", deleteOrgAssignmentsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if deleteOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleDeleteOrgAssignmentsResponse(resp, deleteOrgAssignmentsIncludeResp, deleteOrgAssignmentsVerbose, deleteOrgAssignmentsSilent)
}

func buildDeleteOrgAssignmentsURL(endpoint, version, orgID string) (string, error) {
	// Build base URL with organization ID path parameter
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/learn/assignments", endpoint, orgID)

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

func buildDeleteOrgAssignmentsRequestBody() (string, error) {
	// If raw data is provided, use it directly
	if deleteOrgAssignmentsData != "" {
		return deleteOrgAssignmentsData, nil
	}

	// Validate required parameters when building from flags
	if len(deleteOrgAssignmentsAssignmentIDs) == 0 {
		return "", fmt.Errorf("at least one assignment ID must be provided via --assignment-ids")
	}

	// Build request body according to the API specification
	var assignments []map[string]interface{}

	for _, assignmentID := range deleteOrgAssignmentsAssignmentIDs {
		assignment := map[string]interface{}{
			"id":   assignmentID,
			"type": "lesson_assignment",
		}
		assignments = append(assignments, assignment)
	}

	// Convert to JSON
	jsonData, err := json.Marshal(assignments)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleDeleteOrgAssignmentsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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