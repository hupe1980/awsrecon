package permission

import (
	"fmt"

	"github.com/hupe1980/awsrecon/pkg/iam"
)

type Escalation struct {
	Type    string
	Actions []iam.Action
}

type EngineOptions struct {
	IAMDefinitions             *iam.Definitions
	PrivilegeEscalationMethods map[string][]iam.Action
	DataExfiltrationActions    []iam.Action
}

type Engine struct {
	definitions                *iam.Definitions
	privilegeEscalationMethods map[string][]iam.Action
	dataExfiltrationActions    []iam.Action
}

func NewEngine(optFns ...func(o *EngineOptions)) (*Engine, error) {
	opts := EngineOptions{
		PrivilegeEscalationMethods: DefaultPrivilegeEscalationMethods,
		DataExfiltrationActions:    DefaultDataExfiltrationActions,
	}

	for _, fn := range optFns {
		fn(&opts)
	}

	if opts.IAMDefinitions == nil {
		d, err := iam.NewDefinitions()
		if err != nil {
			return nil, err
		}

		opts.IAMDefinitions = d
	}

	return &Engine{
		definitions:                opts.IAMDefinitions,
		privilegeEscalationMethods: opts.PrivilegeEscalationMethods,
		dataExfiltrationActions:    opts.DataExfiltrationActions,
	}, nil
}

func (e *Engine) AuditEncodedPolicy(encoded string) error {
	policy, err := NewPolicyDocument(e, encoded)
	if err != nil {
		return err
	}

	for _, s := range policy.Statements() {
		//TODO
		fmt.Println(s.Services())
		fmt.Println(s.Actions())
		fmt.Println(s.NotActions())
		fmt.Println(s.ExpandedActions())
		fmt.Println(s.NotActionEffectiveActions())
	}

	return nil
}

func (e *Engine) GetAllActions() []iam.Action {
	return e.definitions.GetActions(&iam.GetActionsInput{})
}
