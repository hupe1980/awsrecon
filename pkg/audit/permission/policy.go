package permission

import (
	"github.com/hupe1980/awsrecon/pkg/common"
	"github.com/hupe1980/awsrecon/pkg/iam"
)

type PolicyDocument struct {
	engine     *Engine
	raw        *iam.PolicyDocument
	statements []*Statement
}

func NewPolicyDocument(engine *Engine, encoded string) (*PolicyDocument, error) {
	raw, err := iam.ConvertToPolicyDocument(encoded)
	if err != nil {
		return nil, err
	}

	statements := []*Statement{}

	for _, rs := range raw.Statements {
		statements = append(statements, NewStatement(engine, rs))
	}

	return &PolicyDocument{
		engine:     engine,
		raw:        raw,
		statements: statements,
	}, nil
}

func (p *PolicyDocument) AllowedPrivilegeEscaltions() []*Escalation {
	escalations := []*Escalation{}

	for k, v := range p.engine.privilegeEscalationMethods {
		if common.SliceContainsSubslice([]iam.Action{"a", "b"}, v) {
			escalations = append(escalations, &Escalation{
				Type:    k,
				Actions: v,
			})
		}
	}

	return escalations
}

func (p *PolicyDocument) AllowedDataExfiltrationActions() []iam.Action {
	results := []iam.Action{}

	for _, m := range p.engine.dataExfiltrationActions {
		if common.SliceContains([]iam.Action{"a", "b"}, m) {
			results = append(results, m)
		}
	}

	return results
}

func (p *PolicyDocument) Version() string {
	return p.raw.Version
}

func (p *PolicyDocument) Statements() []*Statement {
	return p.statements
}

// AllAllowedActions returns all allowed IAM Actions, regardless of resource constraints
func (p *PolicyDocument) AllAllowedActions() []iam.Action {
	results := []iam.Action{}

	for _, s := range p.statements {
		if s.IsAllow() {
			results = append(results, s.ExpandedActions()...)
		}
	}

	return results
}

func (p *PolicyDocument) AllAllowedUnrestrictedActions() []iam.Action {
	results := []iam.Action{}

	for _, s := range p.statements {
		if s.IsAllow() && s.HasResourceWildcard() {
			results = append(results, s.Actions()...)
		}
	}

	return results
}
