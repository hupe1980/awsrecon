package iam

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefinition(t *testing.T) {
	fs := os.DirFS("../../testdata")
	definitions, err := NewDefinitionsFromFS("iam-definition.json", fs, false)
	assert.NoError(t, err)

	t.Run("ServicePrefixes", func(t *testing.T) {
		assert.ElementsMatch(t, []string{"s3", "dynamodb", "ram"}, definitions.ServicePrefixes())
	})

	t.Run("GetServiceDefinition", func(t *testing.T) {
		def := definitions.GetServiceDefinition("dynamodb")

		assert.Equal(t, "Amazon DynamoDB", def.Name)
		assert.Equal(t, "dynamodb", def.Prefix)
	})

	t.Run("GetActions", func(t *testing.T) {
		actions := definitions.GetActions(&GetActionsInput{
			ServicePrefix: "ram",
		})

		assert.ElementsMatch(t, []Action{
			"ram:AcceptResourceShareInvitation",
			"ram:AssociateResourceShare",
			"ram:AssociateResourceSharePermission",
			"ram:CreateResourceShare",
			"ram:DeleteResourceShare",
			"ram:DisassociateResourceShare",
			"ram:DisassociateResourceSharePermission",
			"ram:EnableSharingWithAwsOrganization",
			"ram:GetPermission",
			"ram:GetResourcePolicies",
			"ram:GetResourceShareAssociations",
			"ram:GetResourceShareInvitations",
			"ram:GetResourceShares",
			"ram:ListPendingInvitationResources",
			"ram:ListPermissions",
			"ram:ListPrincipals",
			"ram:ListResourceSharePermissions",
			"ram:ListResources",
			"ram:RejectResourceShareInvitation",
			"ram:TagResource",
			"ram:UntagResource",
			"ram:UpdateResourceShare",
			"ram:PromoteResourceShareCreatedFromPolicy",
			"ram:ListResourceTypes",
			"ram:ListPermissionVersions",
		}, actions)
	})

	t.Run("GetActions - NamePattern", func(t *testing.T) {
		actions := definitions.GetActions(&GetActionsInput{
			ServicePrefix: "dynamodb",
			NamePattern:   "Import*",
		})

		assert.ElementsMatch(t, []Action{"dynamodb:ImportTable"}, actions)
	})

	t.Run("GetActions - AccessLevel", func(t *testing.T) {
		actions := definitions.GetActions(&GetActionsInput{
			ServicePrefix: "dynamodb",
			AccessLevel:   AccessLevelTagging,
		})

		assert.ElementsMatch(t, []Action{"dynamodb:TagResource", "dynamodb:UntagResource"}, actions)
	})

	t.Run("GetActions - AccessLevel & ResourceTypeName #1", func(t *testing.T) {
		actions := definitions.GetActions(&GetActionsInput{
			ServicePrefix:    "s3",
			ResourceTypeName: "bucket",
			AccessLevel:      AccessLevelPermissionsManagement,
		})

		assert.ElementsMatch(t, []Action{
			"s3:DeleteBucketPolicy",
			"s3:PutBucketPolicy",
			"s3:PutBucketPublicAccessBlock",
			"s3:PutBucketAcl",
		}, actions)
	})

	t.Run("GetActions - AccessLevel & ResourceTypeName #2", func(t *testing.T) {
		actions := definitions.GetActions(&GetActionsInput{
			ServicePrefix:    "s3",
			ResourceTypeName: "*",
			AccessLevel:      AccessLevelPermissionsManagement,
		})

		assert.ElementsMatch(t, []Action{
			"s3:PutAccountPublicAccessBlock",
			"s3:PutAccessPointPublicAccessBlock",
		}, actions)
	})

	t.Run("GetActions - AccessLevel & ResourceTypeName #3", func(t *testing.T) {
		actions := definitions.GetActions(&GetActionsInput{
			ServicePrefix:    "s3",
			ResourceTypeName: "object",
			AccessLevel:      AccessLevelList,
		})

		assert.ElementsMatch(t, []Action{"s3:ListMultipartUploadParts"}, actions)
	})

	t.Run("GetActions - No result", func(t *testing.T) {
		actions := definitions.GetActions(&GetActionsInput{
			ServicePrefix: "not existing xyz",
		})

		assert.ElementsMatch(t, []Action{}, actions)
	})

	t.Run("GetActionData", func(t *testing.T) {
		actionData := definitions.GetActionData(Action("ram:TagResource"))

		assert.ElementsMatch(t, []*ActionData{
			{
				Name:              "TagResource",
				Description:       "Grants permission to tag the specified resource share",
				AccessLevel:       "Tagging",
				APIDocLink:        "https://docs.aws.amazon.com/ram/latest/APIReference/API_TagResource.html",
				ResourceARNFormat: "*",
				ConditionKeys:     []string{},
				DependentActions:  []string{},
			},
			{
				Name:              "TagResource",
				Description:       "Grants permission to tag the specified resource share",
				AccessLevel:       "Tagging",
				APIDocLink:        "https://docs.aws.amazon.com/ram/latest/APIReference/API_TagResource.html",
				ResourceARNFormat: "arn:${Partition}:ram:${Region}:${Account}:resource-share/${ResourcePath}",
				ConditionKeys: []string{
					"aws:ResourceTag/${TagKey}",
					"ram:AllowsExternalPrincipals",
					"ram:ResourceShareName",
				},
				DependentActions: []string{},
			},
		}, actionData)
	})
}
