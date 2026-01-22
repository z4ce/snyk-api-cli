package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
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

	// Build request body
	requestBody, err := buildUpdateOrgAssignmentsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateOrgAssignmentsVerbose,
		Silent:      updateOrgAssignmentsSilent,
		IncludeResp: updateOrgAssignmentsIncludeResp,
		UserAgent:   updateOrgAssignmentsUserAgent,
	})
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
