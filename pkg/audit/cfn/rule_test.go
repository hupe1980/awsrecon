package cfn

import (
	"testing"

	"github.com/hupe1980/awsrecon/pkg/cloudformation"
	"github.com/stretchr/testify/assert"
)

func TestPasswordPropertyRule(t *testing.T) {
	rds := &cloudformation.Resource{
		Type: "AWS::RDS::DBInstance",
		Properties: map[string]interface{}{
			"MasterUserPassword": "xxx",
		},
	}

	rule := PasswordPropertyRule{}

	result, err := rule.Audit(rds)

	assert.NoError(t, err)
	assert.Equal(t, "PasswordProperty", result[0].ID)
}
