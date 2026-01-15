package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/z4ce/snyk-api-cli/cmd"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "snyk-api-cli",
	Short: "A CLI tool for exploring the Snyk API",
	Long: `snyk-api-cli is a command-line tool designed to help you explore and interact 
with the Snyk API. It provides curl-like functionality with automatic handling 
of Snyk-specific parameters and endpoints.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Register subcommands
	rootCmd.AddCommand(cmd.CurlCmd)

	// Apps
	rootCmd.AddCommand(cmd.GetAppsCmd)
	rootCmd.AddCommand(cmd.CreateAppCmd)
	rootCmd.AddCommand(cmd.GetAppByIDCmd)
	rootCmd.AddCommand(cmd.GetAppCmd)
	rootCmd.AddCommand(cmd.DeleteAppByIDCmd)
	rootCmd.AddCommand(cmd.DeleteAppCmd)
	rootCmd.AddCommand(cmd.GetAppBotsCmd)
	rootCmd.AddCommand(cmd.DeleteAppBotCmd)
	rootCmd.AddCommand(cmd.UpdateAppCreationByIDCmd)
	rootCmd.AddCommand(cmd.UpdateAppCmd)
	rootCmd.AddCommand(cmd.ManageAppCreationSecretCmd)
	rootCmd.AddCommand(cmd.ManageSecretsCmd)

	// Assets
	rootCmd.AddCommand(cmd.ListAssetsCmd)
	rootCmd.AddCommand(cmd.GetAssetCmd)
	rootCmd.AddCommand(cmd.GetAssetInOrgCmd)
	rootCmd.AddCommand(cmd.ListRelatedAssetsCmd)
	rootCmd.AddCommand(cmd.ListAssetProjectsCmd)
	rootCmd.AddCommand(cmd.ListAssetsInOrgCmd)
	rootCmd.AddCommand(cmd.CreateAssetCmd)

	// Broker operations
	rootCmd.AddCommand(cmd.ListBrokerConnectionsForOrgCmd)
	rootCmd.AddCommand(cmd.GetBrokerConnectionIntegrationsCmd)
	rootCmd.AddCommand(cmd.CreateBrokerConnectionIntegrationCmd)
	rootCmd.AddCommand(cmd.DeleteBrokerConnectionIntegrationCmd)
	rootCmd.AddCommand(cmd.ListBrokerDeploymentsForTenantCmd)
	rootCmd.AddCommand(cmd.ListConnectionContextsCmd)
	rootCmd.AddCommand(cmd.GetConnectionContextCmd)
	rootCmd.AddCommand(cmd.UpdateBrokerContextCmd)
	rootCmd.AddCommand(cmd.DeleteBrokerContextCmd)
	rootCmd.AddCommand(cmd.UpdateBrokerContextIntegrationCmd)
	rootCmd.AddCommand(cmd.DeleteBrokerContextIntegrationCmd)
	rootCmd.AddCommand(cmd.ListBrokerDeploymentsCmd)
	rootCmd.AddCommand(cmd.CreateBrokerDeploymentCmd)
	rootCmd.AddCommand(cmd.UpdateBrokerDeploymentCmd)
	rootCmd.AddCommand(cmd.DeleteBrokerDeploymentCmd)
	rootCmd.AddCommand(cmd.ListBrokerConnectionsCmd)
	rootCmd.AddCommand(cmd.CreateBrokerConnectionCmd)
	rootCmd.AddCommand(cmd.DeleteBrokerConnectionsCmd)
	rootCmd.AddCommand(cmd.GetBrokerConnectionCmd)
	rootCmd.AddCommand(cmd.UpdateBrokerConnectionCmd)
	rootCmd.AddCommand(cmd.DeleteBrokerConnectionCmd)
	rootCmd.AddCommand(cmd.ListBrokerOrgsForBulkMigrationCmd)
	rootCmd.AddCommand(cmd.CreateBrokerOrgsForBulkMigrationCmd)
	rootCmd.AddCommand(cmd.ListDeploymentContextsCmd)
	rootCmd.AddCommand(cmd.CreateBrokerContextCmd)
	rootCmd.AddCommand(cmd.ListDeploymentCredentialsCmd)
	rootCmd.AddCommand(cmd.CreateDeploymentCredentialCmd)
	rootCmd.AddCommand(cmd.GetDeploymentCredentialCmd)
	rootCmd.AddCommand(cmd.UpdateDeploymentCredentialCmd)
	rootCmd.AddCommand(cmd.DeleteDeploymentCredentialCmd)

	// Cloud environments
	rootCmd.AddCommand(cmd.ListEnvironmentsCmd)

	// Cloud resources
	rootCmd.AddCommand(cmd.ListResourcesCmd)

	// Cloud scans
	rootCmd.AddCommand(cmd.ListScanCmd)
	rootCmd.AddCommand(cmd.GetScanCmd)
	rootCmd.AddCommand(cmd.CreateScanCmd)

	// Collections
	rootCmd.AddCommand(cmd.CreateCollectionCmd)
	rootCmd.AddCommand(cmd.UpdateCollectionCmd)
	rootCmd.AddCommand(cmd.UpdateCollectionWithProjectsCmd)
	rootCmd.AddCommand(cmd.GetCollectionsCmd)
	rootCmd.AddCommand(cmd.GetProjectsOfCollectionCmd)
	rootCmd.AddCommand(cmd.GetCollectionCmd)
	rootCmd.AddCommand(cmd.DeleteCollectionCmd)
	rootCmd.AddCommand(cmd.DeleteProjectsCollectionCmd)

	// Container Images
	rootCmd.AddCommand(cmd.ListContainerImageCmd)
	rootCmd.AddCommand(cmd.GetContainerImageCmd)
	rootCmd.AddCommand(cmd.ListImageTargetRefsCmd)

	// Custom Base Images
	rootCmd.AddCommand(cmd.GetCustomBaseImagesCmd)
	rootCmd.AddCommand(cmd.GetCustomBaseImageCmd)
	rootCmd.AddCommand(cmd.CreateCustomBaseImageCmd)
	rootCmd.AddCommand(cmd.UpdateCustomBaseImageCmd)
	rootCmd.AddCommand(cmd.DeleteCustomBaseImageCmd)

	// Groups
	rootCmd.AddCommand(cmd.ListGroupsCmd)
	rootCmd.AddCommand(cmd.GetGroupCmd)
	rootCmd.AddCommand(cmd.GetAppInstallsForGroupCmd)
	rootCmd.AddCommand(cmd.CreateGroupAppInstallCmd)
	rootCmd.AddCommand(cmd.DeleteGroupAppInstallByIdCmd)
	rootCmd.AddCommand(cmd.UpdateGroupAppInstallSecretCmd)
	rootCmd.AddCommand(cmd.ListGroupAuditLogsCmd)
	rootCmd.AddCommand(cmd.CreateGroupExportCmd)
	rootCmd.AddCommand(cmd.GetGroupExportCmd)
	rootCmd.AddCommand(cmd.DeleteGroupExportCmd)
	rootCmd.AddCommand(cmd.ListGroupIssuesCmd)
	rootCmd.AddCommand(cmd.GetGroupIssueByIssueIDCmd)
	rootCmd.AddCommand(cmd.GetGroupExportJobStatusCmd)
	rootCmd.AddCommand(cmd.ListGroupMembershipsCmd)
	rootCmd.AddCommand(cmd.CreateGroupMembershipCmd)
	rootCmd.AddCommand(cmd.UpdateGroupUserMembershipCmd)
	rootCmd.AddCommand(cmd.DeleteGroupMembershipCmd)
	rootCmd.AddCommand(cmd.ListGroupUserOrgMembershipsCmd)
	rootCmd.AddCommand(cmd.ListOrgsInGroupCmd)
	rootCmd.AddCommand(cmd.GetManyGroupServiceAccountCmd)
	rootCmd.AddCommand(cmd.CreateGroupServiceAccountCmd)
	rootCmd.AddCommand(cmd.GetOneGroupServiceAccountCmd)
	rootCmd.AddCommand(cmd.UpdateGroupServiceAccountCmd)
	rootCmd.AddCommand(cmd.DeleteOneGroupServiceAccountCmd)
	rootCmd.AddCommand(cmd.UpdateServiceAccountSecretCmd)
	rootCmd.AddCommand(cmd.GetIacSettingsForGroupCmd)
	rootCmd.AddCommand(cmd.UpdateIacSettingsForGroupCmd)
	rootCmd.AddCommand(cmd.GetPullRequestTemplateCmd)
	rootCmd.AddCommand(cmd.CreateOrUpdatePullRequestTemplateCmd)
	rootCmd.AddCommand(cmd.DeletePullRequestTemplateCmd)
	rootCmd.AddCommand(cmd.ListGroupSsoConnectionsCmd)
	rootCmd.AddCommand(cmd.ListGroupSsoConnectionUsersCmd)

	// Learn catalog
	rootCmd.AddCommand(cmd.ListLearnCatalogCmd)

	// OpenAPI
	rootCmd.AddCommand(cmd.ListAPIVersionsCmd)
	rootCmd.AddCommand(cmd.GetAPIVersionCmd)

	// Organizations
	rootCmd.AddCommand(cmd.ListOrgsCmd)
	rootCmd.AddCommand(cmd.GetOrgCmd)
	rootCmd.AddCommand(cmd.UpdateOrgCmd)
	rootCmd.AddCommand(cmd.CreateExportCmd)
	rootCmd.AddCommand(cmd.ListOrgAuditLogsCmd)
	rootCmd.AddCommand(cmd.GetPermissionsCmd)
	rootCmd.AddCommand(cmd.GetOrgAppsCmd)
	rootCmd.AddCommand(cmd.GetAppInstallsForOrgCmd)
	rootCmd.AddCommand(cmd.CreateOrgAppCmd)
	rootCmd.AddCommand(cmd.CreateOrgAppInstallCmd)
	rootCmd.AddCommand(cmd.DeleteAppOrgInstallByIdCmd)
	rootCmd.AddCommand(cmd.UpdateOrgAppInstallSecretCmd)

	// Organization invitations
	rootCmd.AddCommand(cmd.ListOrgInvitationCmd)
	rootCmd.AddCommand(cmd.CreateOrgInvitationCmd)
	rootCmd.AddCommand(cmd.DeleteOrgInvitationCmd)

	// Organization issues
	rootCmd.AddCommand(cmd.ListOrgIssuesCmd)
	rootCmd.AddCommand(cmd.GetOrgIssueCmd)

	// Organization learn assignments
	rootCmd.AddCommand(cmd.ListOrgAssignmentsCmd)
	rootCmd.AddCommand(cmd.CreateOrgAssignmentsCmd)
	rootCmd.AddCommand(cmd.UpdateOrgAssignmentsCmd)
	rootCmd.AddCommand(cmd.DeleteOrgAssignmentsCmd)

	// Organization memberships
	rootCmd.AddCommand(cmd.ListOrgMembershipsCmd)
	rootCmd.AddCommand(cmd.CreateOrgMembershipCmd)
	rootCmd.AddCommand(cmd.UpdateOrgMembershipCmd)
	rootCmd.AddCommand(cmd.DeleteOrgMembershipCmd)

	// Organization packages
	rootCmd.AddCommand(cmd.ListIssuesForManyPurlsCmd)
	rootCmd.AddCommand(cmd.FetchIssuesPerPurlCmd)

	// Organization policies
	rootCmd.AddCommand(cmd.GetOrgPoliciesCmd)
	rootCmd.AddCommand(cmd.CreateOrgPolicyCmd)
	rootCmd.AddCommand(cmd.GetOrgPolicyCmd)
	rootCmd.AddCommand(cmd.UpdateOrgPolicyCmd)
	rootCmd.AddCommand(cmd.DeleteOrgPolicyCmd)
	rootCmd.AddCommand(cmd.GetOrgPolicyEventsCmd)

	// Organization projects
	rootCmd.AddCommand(cmd.ListOrgProjectsCmd)
	rootCmd.AddCommand(cmd.GetOrgProjectCmd)
	rootCmd.AddCommand(cmd.UpdateOrgProjectCmd)
	rootCmd.AddCommand(cmd.DeleteOrgProjectCmd)

	// Organization service accounts
	rootCmd.AddCommand(cmd.GetManyOrgServiceAccountsCmd)
	rootCmd.AddCommand(cmd.CreateOrgServiceAccountCmd)
	rootCmd.AddCommand(cmd.GetOneOrgServiceAccountCmd)
	rootCmd.AddCommand(cmd.UpdateOrgServiceAccountCmd)
	rootCmd.AddCommand(cmd.DeleteServiceAccountCmd)
	rootCmd.AddCommand(cmd.UpdateOrgServiceAccountSecretCmd)

	// Organization settings
	rootCmd.AddCommand(cmd.GetIacSettingsForOrgCmd)
	rootCmd.AddCommand(cmd.UpdateIacSettingsForOrgCmd)
	rootCmd.AddCommand(cmd.GetSastSettingsCmd)
	rootCmd.AddCommand(cmd.UpdateOrgSastSettingsCmd)

	// SBOM operations
	rootCmd.AddCommand(cmd.GetSbomCmd)
	rootCmd.AddCommand(cmd.CreateSbomTestRunCmd)
	rootCmd.AddCommand(cmd.GetSbomTestStatusCmd)
	rootCmd.AddCommand(cmd.GetSbomTestResultCmd)

	// Self/User endpoints
	rootCmd.AddCommand(cmd.GetSelfCmd)
	rootCmd.AddCommand(cmd.GetAccessRequestsCmd)
	rootCmd.AddCommand(cmd.GetUserInstalledAppsCmd)
	rootCmd.AddCommand(cmd.GetAppInstallsForUserCmd)
	rootCmd.AddCommand(cmd.DeleteUserAppInstallByIdCmd)
	rootCmd.AddCommand(cmd.RevokeUserInstalledAppCmd)
	rootCmd.AddCommand(cmd.GetUserAppSessionsCmd)
	rootCmd.AddCommand(cmd.RevokeUserAppSessionCmd)

	// Slack integrations
	rootCmd.AddCommand(cmd.GetSlackDefaultNotificationSettingsCmd)
	rootCmd.AddCommand(cmd.CreateSlackDefaultNotificationSettingsCmd)
	rootCmd.AddCommand(cmd.DeleteSlackDefaultNotificationSettingsCmd)
	rootCmd.AddCommand(cmd.GetSlackProjectNotificationSettingsCollectionCmd)
	rootCmd.AddCommand(cmd.CreateSlackProjectNotificationSettingsCmd)
	rootCmd.AddCommand(cmd.UpdateSlackProjectNotificationSettingsCmd)
	rootCmd.AddCommand(cmd.DeleteSlackProjectNotificationSettingsCmd)
	rootCmd.AddCommand(cmd.ListChannelsCmd)
	rootCmd.AddCommand(cmd.GetChannelNameByIdCmd)

	// Targets
	rootCmd.AddCommand(cmd.GetOrgsTargetsCmd)
	rootCmd.AddCommand(cmd.GetOrgsTargetCmd)
	rootCmd.AddCommand(cmd.DeleteOrgsTargetCmd)

	// Tenants
	rootCmd.AddCommand(cmd.ListTenantsCmd)
	rootCmd.AddCommand(cmd.GetTenantCmd)
	rootCmd.AddCommand(cmd.UpdateTenantCmd)
	rootCmd.AddCommand(cmd.ListTenantLearningProgramsCmd)
	rootCmd.AddCommand(cmd.GetTenantMembershipsCmd)
	rootCmd.AddCommand(cmd.UpdateTenantMembershipCmd)
	rootCmd.AddCommand(cmd.DeleteTenantMembershipCmd)
	rootCmd.AddCommand(cmd.ListTenantRolesCmd)
	rootCmd.AddCommand(cmd.CreateTenantRoleCmd)
	rootCmd.AddCommand(cmd.GetTenantRoleCmd)
	rootCmd.AddCommand(cmd.UpdateTenantRoleCmd)
	rootCmd.AddCommand(cmd.DeleteTenantRoleCmd)

	// Users
	rootCmd.AddCommand(cmd.GetUserCmd)
	rootCmd.AddCommand(cmd.UpdateUserCmd)
	rootCmd.AddCommand(cmd.DeleteUserCmd)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.snyk-api-cli.yaml)")
	rootCmd.PersistentFlags().String("endpoint", "api.snyk.io", "Snyk API endpoint")
	rootCmd.PersistentFlags().String("version", "2024-10-15", "API version for REST endpoints")

	// OAuth2 client credentials flags
	rootCmd.PersistentFlags().String("client-id", "", "OAuth2 client ID for client credentials authentication")
	rootCmd.PersistentFlags().String("client-secret", "", "OAuth2 client secret for client credentials authentication")

	// Bind flags to viper
	viper.BindPFlag("endpoint", rootCmd.PersistentFlags().Lookup("endpoint"))
	viper.BindPFlag("version", rootCmd.PersistentFlags().Lookup("version"))
	viper.BindPFlag("client-id", rootCmd.PersistentFlags().Lookup("client-id"))
	viper.BindPFlag("client-secret", rootCmd.PersistentFlags().Lookup("client-secret"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".snyk-api-cli" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".snyk-api-cli")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func main() {
	Execute()
}
