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

// UpdateOrgAssignmentsCmd represents the update-org-assignments command
var UpdateOrgAssignmentsCmd = &cobra.Command{
	Use:   "update-org-assignments [org_id]",
	Short: "Update due date for assignments in an organization",
	Long: `Update due date for assignments in an organization using the Snyk Learn API.

This command allows an admin to update the due date for existing assignments within their organization.
You must provide either the assignment data as JSON using the --data flag, or specify the assignment IDs
and new due date using the available flags.

Examples:
  snyk-api-cli update-org-assignments 12345678-1234-1234-1234-123456789012 --data '{"data":{"type":"assignment_update","id":"12345","attributes":{"assignments_ids":["assign1","assign2"],"due_date":"2024-12-31T23:59:59Z"}}}'
  snyk-api-cli update-org-assignments 12345678-1234-1234-1234-123456789012 --assignment-ids "assign1,assign2" --due-date "2024-12-31T23:59:59Z"
  snyk-api-cli update-org-assignments 12345678-1234-1234-1234-123456789012 --assignment-ids "assign1" --due-date "2024-12-31T23:59:59Z" --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runUpdateOrgAssignments,
}

var (
	updateOrgAssignmentsData          string
	updateOrgAssignmentsAssignmentIDs []string
	updateOrgAssignmentsDueDate       string
	updateOrgAssignmentsID            string
	updateOrgAssignmentsVerbose       bool
	updateOrgAssignmentsSilent        bool
	updateOrgAssignmentsIncludeResp   bool
	updateOrgAssignmentsUserAgent     string
)

func init() {
	// Add flags for request body attributes
	UpdateOrgAssignmentsCmd.Flags().StringVar(&updateOrgAssignmentsData, "data", "", "JSON data for the request body (if provided, other flags are ignored)")
	UpdateOrgAssignmentsCmd.Flags().StringSliceVar(&updateOrgAssignmentsAssignmentIDs, "assignment-ids", []string{}, "Comma-separated list of assignment IDs to update (required)")
	UpdateOrgAssignmentsCmd.Flags().StringVar(&updateOrgAssignmentsDueDate, "due-date", "", "New due date for assignments (RFC3339 format, e.g., 2024-12-31T23:59:59Z) (required)")
	UpdateOrgAssignmentsCmd.Flags().StringVar(&updateOrgAssignmentsID, "id", "", "ID for the update operation (if not provided, a UUID will be generated)")

	// Add standard flags like other commands
	UpdateOrgAssignmentsCmd.Flags().BoolVarP(&updateOrgAssignmentsVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateOrgAssignmentsCmd.Flags().BoolVarP(&updateOrgAssignmentsSilent, "silent", "s", false, "Silent mode")
	UpdateOrgAssignmentsCmd.Flags().BoolVarP(&updateOrgAssignmentsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateOrgAssignmentsCmd.Flags().StringVarP(&updateOrgAssignmentsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runUpdateOrgAssignments(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateOrgAssignmentsURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	if updateOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Requesting PATCH %s\n", fullURL)
	}

	// Build request body
	requestBody, err := buildUpdateOrgAssignmentsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	if updateOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Request body: %s\n", requestBody)
	}

	// Create the HTTP request
	req, err := http.NewRequest("PATCH", fullURL, strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set content type for JSON:API
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Handle authentication with same precedence as curl: Authorization header > SNYK_TOKEN > OAuth
	if updateOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Checking authentication options\n")
	}

	authHeader, err := buildAuthHeader([]string{}) // No manual headers for this command
	if err != nil {
		if updateOrgAssignmentsVerbose {
			fmt.Fprintf(os.Stderr, "* Warning: failed to get automatic auth: %v\n", err)
		}
		// Don't fail the request, just proceed without automatic auth
	} else if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
		if updateOrgAssignmentsVerbose {
			fmt.Fprintf(os.Stderr, "* Added automatic authorization header\n")
		}
	} else if updateOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* No automatic authorization available\n")
	}

	// Set user agent
	req.Header.Set("User-Agent", updateOrgAssignmentsUserAgent)

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if updateOrgAssignmentsVerbose {
		fmt.Fprintf(os.Stderr, "* Making request...\n")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response using the same pattern as other commands
	return handleUpdateOrgAssignmentsResponse(resp, updateOrgAssignmentsIncludeResp, updateOrgAssignmentsVerbose, updateOrgAssignmentsSilent)
}

func buildUpdateOrgAssignmentsURL(endpoint, version, orgID string) (string, error) {
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

func buildUpdateOrgAssignmentsRequestBody() (string, error) {
	// If raw data is provided, use it directly
	if updateOrgAssignmentsData != "" {
		return updateOrgAssignmentsData, nil
	}

	// Validate required parameters when building from flags
	if len(updateOrgAssignmentsAssignmentIDs) == 0 {
		return "", fmt.Errorf("at least one assignment ID must be provided via --assignment-ids")
	}
	if updateOrgAssignmentsDueDate == "" {
		return "", fmt.Errorf("due date must be provided via --due-date")
	}

	// Generate ID if not provided
	id := updateOrgAssignmentsID
	if id == "" {
		// Use a simple timestamp-based ID
		id = fmt.Sprintf("update-%d", time.Now().Unix())
	}

	// Build request body according to the API specification
	data := map[string]interface{}{
		"type": "assignment_update",
		"id":   id,
		"attributes": map[string]interface{}{
			"assignments_ids": updateOrgAssignmentsAssignmentIDs,
			"due_date":        updateOrgAssignmentsDueDate,
		},
	}

	requestData := map[string]interface{}{
		"data": data,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}

func handleUpdateOrgAssignmentsResponse(resp *http.Response, includeResp, verbose, silent bool) error {
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