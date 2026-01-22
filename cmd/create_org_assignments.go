package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CreateOrgAssignmentsCmd represents the create-org-assignments command
var CreateOrgAssignmentsCmd = &cobra.Command{
	Use:   "create-org-assignments [org_id]",
	Short: "Bulk creation of assignments for users in an organization",
	Long: `Bulk creation of assignments for users in an organization using the Snyk Learn API.

This command creates assignments for users within the specified organization.
You must provide the assignment data as JSON using the --data flag, or specify
individual assignment parameters using the available flags.

Examples:
  snyk-api-cli create-org-assignments 12345678-1234-1234-1234-123456789012 --data '{"data":[{"type":"lesson_assignment","attributes":{"lesson_id":"123","user_id":"456"}}]}'
  snyk-api-cli create-org-assignments 12345678-1234-1234-1234-123456789012 --lesson-ids "lesson1,lesson2" --user-ids "user1,user2" --due-date "2024-12-31T23:59:59Z"
  snyk-api-cli create-org-assignments 12345678-1234-1234-1234-123456789012 --lesson-ids "lesson1" --user-ids "user1" --email-notification --email-receive-copy --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCreateOrgAssignments,
}

var (
	createOrgAssignmentsData                string
	createOrgAssignmentsLessonIDs           []string
	createOrgAssignmentsUserIDs             []string
	createOrgAssignmentsDueDate             string
	createOrgAssignmentsEmailCustomMsg      string
	createOrgAssignmentsEmailNotification   bool
	createOrgAssignmentsEmailReceiveCopy    bool
	createOrgAssignmentsResetProgress       bool
	createOrgAssignmentsResetProgressBefore string
	createOrgAssignmentsVerbose             bool
	createOrgAssignmentsSilent              bool
	createOrgAssignmentsIncludeResp         bool
	createOrgAssignmentsUserAgent           string
)

func init() {
	// Add flags for request body attributes
	CreateOrgAssignmentsCmd.Flags().StringVar(&createOrgAssignmentsData, "data", "", "JSON data for the request body (if provided, other flags are ignored)")
	CreateOrgAssignmentsCmd.Flags().StringSliceVar(&createOrgAssignmentsLessonIDs, "lesson-ids", []string{}, "Comma-separated list of lesson IDs to assign")
	CreateOrgAssignmentsCmd.Flags().StringSliceVar(&createOrgAssignmentsUserIDs, "user-ids", []string{}, "Comma-separated list of user IDs to assign lessons to")
	CreateOrgAssignmentsCmd.Flags().StringVar(&createOrgAssignmentsDueDate, "due-date", "", "Due date for assignments (RFC3339 format, e.g., 2024-12-31T23:59:59Z)")
	CreateOrgAssignmentsCmd.Flags().StringVar(&createOrgAssignmentsEmailCustomMsg, "email-custom-message", "", "Custom message to include in email notifications")
	CreateOrgAssignmentsCmd.Flags().BoolVar(&createOrgAssignmentsEmailNotification, "email-notification", false, "Send email notifications for assignments")
	CreateOrgAssignmentsCmd.Flags().BoolVar(&createOrgAssignmentsEmailReceiveCopy, "email-receive-copy", false, "Receive a copy of email notifications")
	CreateOrgAssignmentsCmd.Flags().BoolVar(&createOrgAssignmentsResetProgress, "reset-learning-progress", false, "Reset learning progress for assigned lessons")
	CreateOrgAssignmentsCmd.Flags().StringVar(&createOrgAssignmentsResetProgressBefore, "reset-progress-before", "", "Reset progress only if it was made before this date (RFC3339 format)")

	// Add standard flags like other commands
	CreateOrgAssignmentsCmd.Flags().BoolVarP(&createOrgAssignmentsVerbose, "verbose", "v", false, "Make the operation more talkative")
	CreateOrgAssignmentsCmd.Flags().BoolVarP(&createOrgAssignmentsSilent, "silent", "s", false, "Silent mode")
	CreateOrgAssignmentsCmd.Flags().BoolVarP(&createOrgAssignmentsIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	CreateOrgAssignmentsCmd.Flags().StringVarP(&createOrgAssignmentsUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runCreateOrgAssignments(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildCreateOrgAssignmentsURL(endpoint, version, orgID)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildCreateOrgAssignmentsRequestBody()
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "POST",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/vnd.api+json",
		Verbose:     createOrgAssignmentsVerbose,
		Silent:      createOrgAssignmentsSilent,
		IncludeResp: createOrgAssignmentsIncludeResp,
		UserAgent:   createOrgAssignmentsUserAgent,
	})
}

func buildCreateOrgAssignmentsURL(endpoint, version, orgID string) (string, error) {
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

func buildCreateOrgAssignmentsRequestBody() (string, error) {
	// If raw data is provided, use it directly
	if createOrgAssignmentsData != "" {
		return createOrgAssignmentsData, nil
	}

	// Validate required parameters when building from flags
	if len(createOrgAssignmentsLessonIDs) == 0 {
		return "", fmt.Errorf("at least one lesson ID must be provided via --lesson-ids")
	}
	if len(createOrgAssignmentsUserIDs) == 0 {
		return "", fmt.Errorf("at least one user ID must be provided via --user-ids")
	}

	// Build assignment data from flags
	var assignments []map[string]interface{}

	// Create assignment for each user-lesson combination
	for _, userID := range createOrgAssignmentsUserIDs {
		for _, lessonID := range createOrgAssignmentsLessonIDs {
			assignment := map[string]interface{}{
				"type": "lesson_assignment",
				"attributes": map[string]interface{}{
					"lesson_id": lessonID,
					"user_id":   userID,
				},
			}

			// Add optional attributes if provided
			attributes := assignment["attributes"].(map[string]interface{})

			if createOrgAssignmentsDueDate != "" {
				attributes["due_date"] = createOrgAssignmentsDueDate
			}
			if createOrgAssignmentsEmailCustomMsg != "" {
				attributes["email_custom_message"] = createOrgAssignmentsEmailCustomMsg
			}
			if createOrgAssignmentsEmailNotification {
				attributes["email_notification"] = createOrgAssignmentsEmailNotification
			}
			if createOrgAssignmentsEmailReceiveCopy {
				attributes["email_receive_copy"] = createOrgAssignmentsEmailReceiveCopy
			}
			if createOrgAssignmentsResetProgress {
				attributes["reset_learning_progress"] = createOrgAssignmentsResetProgress
			}
			if createOrgAssignmentsResetProgressBefore != "" {
				attributes["reset_progress_before"] = createOrgAssignmentsResetProgressBefore
			}

			assignments = append(assignments, assignment)
		}
	}

	requestData := map[string]interface{}{
		"data": assignments,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
