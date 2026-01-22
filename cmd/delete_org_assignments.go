package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

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

	// Build request body
	requestBody, err := buildDeleteOrgAssignmentsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     deleteOrgAssignmentsVerbose,
		Silent:      deleteOrgAssignmentsSilent,
		IncludeResp: deleteOrgAssignmentsIncludeResp,
		UserAgent:   deleteOrgAssignmentsUserAgent,
	})
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
