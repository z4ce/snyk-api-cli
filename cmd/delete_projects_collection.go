package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DeleteProjectsCollectionCmd represents the delete-projects-collection command
var DeleteProjectsCollectionCmd = &cobra.Command{
	Use:   "delete-projects-collection [org_id] [collection_id]",
	Short: "Remove projects from a collection by specifying an array of project ids",
	Long: `Remove projects from a collection by specifying an array of project ids.

This command removes specific projects from a designated collection within an organization.
Both org_id and collection_id parameters are required and must be valid UUIDs.
Project IDs are specified using the --project-id flag, which can be used multiple times.

Examples:
  snyk-api-cli delete-projects-collection 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --project-id proj-123 --project-id proj-456
  snyk-api-cli delete-projects-collection --verbose 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --project-id proj-123
  snyk-api-cli delete-projects-collection --include 12345678-1234-5678-9012-123456789012 87654321-4321-8765-2109-876543210987 --project-id proj-123`,
	Args: cobra.ExactArgs(2),
	RunE: runDeleteProjectsCollection,
}

var (
	deleteProjectsCollectionVerbose     bool
	deleteProjectsCollectionSilent      bool
	deleteProjectsCollectionIncludeResp bool
	deleteProjectsCollectionUserAgent   string
	deleteProjectsCollectionProjectIds  []string
)

func init() {
	// Add standard flags like curl command
	DeleteProjectsCollectionCmd.Flags().BoolVarP(&deleteProjectsCollectionVerbose, "verbose", "v", false, "Make the operation more talkative")
	DeleteProjectsCollectionCmd.Flags().BoolVarP(&deleteProjectsCollectionSilent, "silent", "s", false, "Silent mode")
	DeleteProjectsCollectionCmd.Flags().BoolVarP(&deleteProjectsCollectionIncludeResp, "include", "i", false, "Include HTTP response headers in output")
	DeleteProjectsCollectionCmd.Flags().StringVarP(&deleteProjectsCollectionUserAgent, "user-agent", "A", "snyk-api-cli/1.0", "User agent string to send")

	// Add request body flags based on API spec
	DeleteProjectsCollectionCmd.Flags().StringSliceVar(&deleteProjectsCollectionProjectIds, "project-id", []string{}, "Project ID to remove from collection (can be used multiple times)")

	// Make project-id flag required
	DeleteProjectsCollectionCmd.MarkFlagRequired("project-id")
}

func runDeleteProjectsCollection(cmd *cobra.Command, args []string) error {
	orgID := args[0]
	collectionID := args[1]
	endpoint := viper.GetString("endpoint")
	version := viper.GetString("version")

	// Build the URL with the org_id and collection_id path parameters
	fullURL, err := buildDeleteProjectsCollectionURL(endpoint, orgID, collectionID, version)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	// Build request body
	requestBody, err := buildDeleteProjectsCollectionRequestBody(deleteProjectsCollectionProjectIds)
	if err != nil {
		return fmt.Errorf("failed to build request body: %w", err)
	}

	return ExecuteAPIRequest(RequestOptions{
		Method:      "DELETE",
		URL:         fullURL,
		Body:        requestBody,
		ContentType: "application/json",
		Verbose:     deleteProjectsCollectionVerbose,
		Silent:      deleteProjectsCollectionSilent,
		IncludeResp: deleteProjectsCollectionIncludeResp,
		UserAgent:   deleteProjectsCollectionUserAgent,
	})
}

func buildDeleteProjectsCollectionURL(endpoint, orgID, collectionID, version string) (string, error) {
	// Validate the org_id parameter
	if strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("org_id cannot be empty")
	}

	// Validate the collection_id parameter
	if strings.TrimSpace(collectionID) == "" {
		return "", fmt.Errorf("collection_id cannot be empty")
	}

	// Build base URL with the path parameters
	baseURL := fmt.Sprintf("https://%s/rest/orgs/%s/collections/%s/relationships/projects", endpoint, orgID, collectionID)

	// Parse URL to handle query parameters properly
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Add required version query parameter
	q := u.Query()
	q.Set("version", version)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func buildDeleteProjectsCollectionRequestBody(projectIds []string) (string, error) {
	if len(projectIds) == 0 {
		return "", fmt.Errorf("at least one project ID must be specified")
	}

	// Build the request body according to API spec
	requestData := struct {
		Data []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"data"`
	}{}

	for _, projectId := range projectIds {
		if strings.TrimSpace(projectId) == "" {
			return "", fmt.Errorf("project ID cannot be empty")
		}
		requestData.Data = append(requestData.Data, struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}{
			ID:   strings.TrimSpace(projectId),
			Type: "project",
		})
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	return string(jsonData), nil
}
