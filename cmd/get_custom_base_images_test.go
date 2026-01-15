package cmd

import (
	"strings"
	"testing"
)

func TestBuildGetCustomBaseImagesURL(t *testing.T) {
	tests := []struct {
		name              string
		endpoint          string
		version           string
		projectID         string
		orgID             string
		groupID           string
		sortBy            string
		sortDirection     string
		repository        string
		tag               string
		includeInRecs     bool
		startingAfter     string
		endingBefore      string
		limit             int
		expectedURL       string
		expectedContains  []string
	}{
		{
			name:     "basic URL with version only",
			endpoint: "api.snyk.io",
			version:  "2024-10-15",
			expectedURL: "https://api.snyk.io/rest/custom_base_images?version=2024-10-15",
		},
		{
			name:        "URL with project ID",
			endpoint:    "api.snyk.io",
			version:     "2024-10-15",
			projectID:   "test-project",
			expectedContains: []string{"version=2024-10-15", "project_id=test-project"},
		},
		{
			name:        "URL with all parameters",
			endpoint:    "api.snyk.io",
			version:     "2024-10-15",
			projectID:   "test-project",
			orgID:       "test-org",
			groupID:     "test-group",
			sortBy:      "repository",
			sortDirection: "DESC",
			repository:  "test-repo",
			tag:         "test-tag",
			includeInRecs: true,
			startingAfter: "cursor1",
			endingBefore:  "cursor2",
			limit:        10,
			expectedContains: []string{
				"version=2024-10-15",
				"project_id=test-project",
				"org_id=test-org",
				"group_id=test-group",
				"sort_by=repository",
				"sort_direction=DESC",
				"repository=test-repo",
				"tag=test-tag",
				"include_in_recommendations=true",
				"starting_after=cursor1",
				"ending_before=cursor2",
				"limit=10",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set global variables
			projectID = tt.projectID
			orgID = tt.orgID
			groupID = tt.groupID
			sortBy = tt.sortBy
			sortDirection = tt.sortDirection
			repository = tt.repository
			tag = tt.tag
			includeInRecommendations = tt.includeInRecs
			startingAfter = tt.startingAfter
			endingBefore = tt.endingBefore
			limit = tt.limit

			// Build URL
			url, err := buildGetCustomBaseImagesURL(tt.endpoint, tt.version)
			if err != nil {
				t.Fatalf("buildGetCustomBaseImagesURL() error = %v", err)
			}

			// Check exact URL if provided
			if tt.expectedURL != "" {
				if url != tt.expectedURL {
					t.Errorf("buildGetCustomBaseImagesURL() = %v, want %v", url, tt.expectedURL)
				}
			}

			// Check that URL contains expected parameters
			for _, expected := range tt.expectedContains {
				if !strings.Contains(url, expected) {
					t.Errorf("URL %v does not contain expected parameter %v", url, expected)
				}
			}

			// Basic validation
			if !strings.HasPrefix(url, "https://") {
				t.Errorf("URL should start with https://")
			}
			if !strings.Contains(url, "/rest/custom_base_images") {
				t.Errorf("URL should contain /rest/custom_base_images")
			}
			if !strings.Contains(url, "version=") {
				t.Errorf("URL should always contain version parameter")
			}
		})
	}
}