package cmd

import (
	"testing"
)

func TestBuildListGroupAuditLogsURL(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		version     string
		groupID     string
		setupFlags  func()
		expected    string
		expectError bool
	}{
		{
			name:     "Basic URL construction",
			endpoint: "api.snyk.io",
			version:  "2024-10-15",
			groupID:  "12345678-1234-1234-1234-123456789012",
			setupFlags: func() {
				// Reset all flags
				listGroupAuditLogsCursor = ""
				listGroupAuditLogsFrom = ""
				listGroupAuditLogsTo = ""
				listGroupAuditLogsSize = 0
				listGroupAuditLogsSortOrder = ""
				listGroupAuditLogsUserID = ""
				listGroupAuditLogsProjectID = ""
				listGroupAuditLogsEvents = ""
				listGroupAuditLogsExcludeEvents = ""
			},
			expected: "https://api.snyk.io/rest/groups/12345678-1234-1234-1234-123456789012/audit_logs/search?version=2024-10-15",
		},
		{
			name:     "URL with date range",
			endpoint: "api.snyk.io",
			version:  "2024-10-15",
			groupID:  "test-group",
			setupFlags: func() {
				listGroupAuditLogsCursor = ""
				listGroupAuditLogsFrom = "2024-01-01T00:00:00Z"
				listGroupAuditLogsTo = "2024-01-31T23:59:59Z"
				listGroupAuditLogsSize = 10
				listGroupAuditLogsSortOrder = "DESC"
				listGroupAuditLogsUserID = ""
				listGroupAuditLogsProjectID = ""
				listGroupAuditLogsEvents = ""
				listGroupAuditLogsExcludeEvents = ""
			},
			expected: "https://api.snyk.io/rest/groups/test-group/audit_logs/search?from=2024-01-01T00%3A00%3A00Z&size=10&sort_order=DESC&to=2024-01-31T23%3A59%3A59Z&version=2024-10-15",
		},
		{
			name:     "URL with all filters",
			endpoint: "api.snyk.io",
			version:  "2024-10-15",
			groupID:  "test-group",
			setupFlags: func() {
				listGroupAuditLogsCursor = "next-page-123"
				listGroupAuditLogsFrom = ""
				listGroupAuditLogsTo = ""
				listGroupAuditLogsSize = 0
				listGroupAuditLogsSortOrder = ""
				listGroupAuditLogsUserID = "user-456"
				listGroupAuditLogsProjectID = "project-789"
				listGroupAuditLogsEvents = "user.created,user.updated"
				listGroupAuditLogsExcludeEvents = "user.deleted"
			},
			expected: "https://api.snyk.io/rest/groups/test-group/audit_logs/search?cursor=next-page-123&events=user.created%2Cuser.updated&exclude_events=user.deleted&project_id=project-789&user_id=user-456&version=2024-10-15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupFlags()
			result, err := buildListGroupAuditLogsURL(tt.endpoint, tt.version, tt.groupID)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Expected URL: %s, got: %s", tt.expected, result)
				}
			}
		})
	}
}