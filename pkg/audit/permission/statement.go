package permission

import (
	"github.com/hupe1980/awsrecon/pkg/common"
	"github.com/hupe1980/awsrecon/pkg/iam"
)

type Statement struct {
	engine *Engine
	raw    *iam.Statement
}

func NewStatement(engine *Engine, s iam.Statement) *Statement {
	return &Statement{
		engine: engine,
		raw:    &s,
	}
}

func (s *Statement) Effect() iam.Effect {
	return s.raw.Effect
}

func (s *Statement) IsAllow() bool {
	return s.Effect() == iam.EffectAllow
}

func (s *Statement) IsDeny() bool {
	return s.Effect() == iam.EffectDeny
}

func (s *Statement) Actions() []iam.Action {
	return s.raw.Action
}

func (s *Statement) NotActions() []iam.Action {
	return s.raw.NotAction
}

func (s *Statement) ExpandedActions() []iam.Action {
	return s.expandActions(s.Actions())
}

func (s *Statement) NotActionEffectiveActions() []iam.Action {
	effectiveActions := []iam.Action{}

	if s.NotActions() != nil && len(s.NotActions()) > 0 {
		expandedNotActions := s.expandActions(s.NotActions())

		if s.IsAllow() && s.HasResourceWildcard() {
			for _, a := range s.engine.GetAllActions() {
				if !common.SliceContains(expandedNotActions, a) {
					effectiveActions = append(effectiveActions, a)
				}
			}
		}
	}

	return effectiveActions
}

func (s *Statement) Services() []string {
	services := common.NewSet[string]()

	for _, a := range s.Actions() {
		services.Put(a.ServicePrefix())
	}

	return services.ToSlice()
}

func (s *Statement) Resources() []iam.Resource {
	return s.raw.Resource
}

func (s *Statement) NotResources() []iam.Resource {
	return s.raw.NotResource
}

func (s *Statement) HasConditions() bool {
	return s.raw.Condition != nil
}

func (s *Statement) HasResourceWildcard() bool {
	return common.SliceContains(s.raw.Resource, "*")
}

// expandActions expands the action with wildcards into full actions
func (s *Statement) expandActions(actions []iam.Action) []iam.Action {
	result := []iam.Action{}

	for _, a := range actions {
		if a.HasWildcard() {
			for _, expendedAction := range s.engine.GetAllActions() {
				if common.WildcardMatch(string(a), string(expendedAction)) {
					result = append(result, expendedAction)
				}
			}
		} else {
			result = append(result, a)
		}
	}

	return result
}
