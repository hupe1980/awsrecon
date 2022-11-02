package permission

import (
	"testing"

	"github.com/hupe1980/awsrecon/pkg/iam"
	"github.com/stretchr/testify/assert"
)

func TestStatement(t *testing.T) {
	engine, err := NewEngine()
	assert.NoError(t, err)

	st := NewStatement(engine, iam.Statement{
		Effect: iam.EffectAllow,
		Action: iam.StatementValue[iam.Action]{
			"iam:PassRole",
			"ec2:DescribeIamInstanceProfileAssociations",
		},
		Resource: iam.StatementValue[iam.Resource]{"*"},
	})

	t.Run("actions", func(t *testing.T) {
		expected := []iam.Action{
			"iam:PassRole",
			"ec2:DescribeIamInstanceProfileAssociations",
		}

		assert.ElementsMatch(t, expected, st.Actions())
	})

	t.Run("services", func(t *testing.T) {
		expected := []string{"iam", "ec2"}

		assert.ElementsMatch(t, expected, st.Services())
	})
}
