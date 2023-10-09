package recon

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
)

type MockRoleTrustsIAMClient struct {
	ListRolesOutput *iam.ListRolesOutput
	ListRolesError  error
}

func (m *MockRoleTrustsIAMClient) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return m.ListRolesOutput, m.ListRolesError
}

func TestRoleTrustsRecon(t *testing.T) {
	r := &RoleTrustsRecon{
		iamClient: &MockRoleTrustsIAMClient{
			ListRolesOutput: &iam.ListRolesOutput{
				Roles: []iamTypes.Role{
					{
						Arn:      aws.String("foo"),
						RoleName: aws.String("foo"),
					},
				},
			},
			ListRolesError: nil,
		},
	}

	r.recon = newRecon[RoleTrust](func() {
		r.runEnumerateService("iam", func() {
			r.enumerateRoleTrusts()
		})
	})

	roleTrusts := r.Run()

	assert.ElementsMatch(t, nil, roleTrusts)
}
