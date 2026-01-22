package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// UpdateOrgProjectCmd represents the update-org-project command
var UpdateOrgProjectCmd = &cobra.Command{
	Use:   "update-org-project [org_id] [project_id]",
	Short: "Update a project by ID in a Snyk organization",
	Long: `Update a project by ID in a Snyk organization.

This command updates a project in the specified organization using the Snyk API.
Both org_id and project_id parameters are required and should be valid UUIDs.

Required permissions: View Organization, View Projects, Edit Projects

Examples:
  snyk-api-cli update-org-project 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --business-criticality "high" --environment "production"
  snyk-api-cli update-org-project 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --lifecycle "development" --test-frequency "weekly"
  snyk-api-cli update-org-project 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --tags "key1=value1,key2=value2"
  snyk-api-cli update-org-project 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --expand "target" --verbose`,
	Args: cobra.ExactArgs(2),
	RunE: runUpdateOrgProject,
}

var (
	updateOrgProjectBusinessCriticality []string
	updateOrgProjectEnvironment         []string
	updateOrgProjectLifecycle           []string
	updateOrgProjectTags                []string
	updateOrgProjectTestFrequency       string
	updateOrgProjectExpand              []string
	updateOrgProjectVerbose             bool
	updateOrgProjectSilent              bool
	updateOrgProjectIncludeResp         bool
	updateOrgProjectUserAgent           string
)

func init() {
	// Add flags for request body attributes
	UpdateOrgProjectCmd.Flags().StringSliceVar(&updateOrgProjectBusinessCriticality, "business-criticality", []string{}, "Business criticality levels")
	UpdateOrgProjectCmd.Flags().StringSliceVar(&updateOrgProjectEnvironment, "environment", []string{}, "Environment types")
	UpdateOrgProjectCmd.Flags().StringSliceVar(&updateOrgProjectLifecycle, "lifecycle", []string{}, "Lifecycle stages")
	UpdateOrgProjectCmd.Flags().StringSliceVar(&updateOrgProjectTags, "tags", []string{}, "Key-value pair tags (format: key=value)")
	UpdateOrgProjectCmd.Flags().StringVar(&updateOrgProjectTestFrequency, "test-frequency", "", "Test frequency setting")

	// Add query parameter flags
	UpdateOrgProjectCmd.Flags().StringSliceVar(&updateOrgProjectExpand, "expand", []string{}, "Expand relationships (e.g., 'target')")

	// Add standard flags like other commands
	UpdateOrgProjectCmd.Flags().BoolVarP(&updateOrgProjectVerbose, "verbose", "v", false, "Make the operation more talkative")
	UpdateOrgProjectCmd.Flags().BoolVarP(&updateOrgProjectSilent, "silent", "s", false, "Silent mode")
	UpdateOrgProjectCmd.Flags().BoolVarP(&updateOrgProjectIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	UpdateOrgProjectCmd.Flags().StringVarP(&updateOrgProjectUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")
}

func runUpdateOrgProject(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	projectID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL
	fullURL, err := buildUpdateOrgProjectURL(endpoint, orgID, projectID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildUpdateOrgProjectRequestBody(projectID)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "PATCH",
		URL:         fullURL,
		Body:        requestBody,
		Verbose:     updateOrgProjectVerbose,
		Silent:      updateOrgProjectSilent,
		IncludeResp: updateOrgProjectIncludeResp,
		UserAgent:   updateOrgProjectUserAgent,
	})
}

func buildUpdateOrgProjectURL(endpoint, orgID, projectID, version string) (string, error) {
	// Build base URL
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

	// Add optional expand parameter
	if len(updateOrgProjectExpand) > 0 {
		for _, expand := range updateOrgProjectExpand {
			q.Add("expand", expand)
		}
	}

	u.RawQuery = q.Encode()
	return u.String(), nil
}

func buildUpdateOrgProjectRequestBody(projectID string) (string, error) {
	// Build JSON:API format request body
	data := map[string]interface{}{
		"type": "project",
		"id":   projectID,
	}

	// Build attributes object
	attributes := make(map[string]interface{})

	if len(updateOrgProjectBusinessCriticality) > 0 {
		attributes["business_criticality"] = updateOrgProjectBusinessCriticality
	}

	if len(updateOrgProjectEnvironment) > 0 {
		attributes["environment"] = updateOrgProjectEnvironment
	}

	if len(updateOrgProjectLifecycle) > 0 {
		attributes["lifecycle"] = updateOrgProjectLifecycle
	}

	if updateOrgProjectTestFrequency != "" {
		attributes["test_frequency"] = updateOrgProjectTestFrequency
	}

	if len(updateOrgProjectTags) > 0 {
		tags := make(map[string]string)
		for _, tag := range updateOrgProjectTags {
			parts := strings.SplitN(tag, "=", 2)
			if len(parts) == 2 {
				tags[parts[0]] = parts[1]
			}
		}
		if len(tags) > 0 {
			attributes["tags"] = tags
		}
	}

	// Add attributes if any were provided
	if len(attributes) > 0 {
		data["attributes"] = attributes
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
