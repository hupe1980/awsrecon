package iam

import (
	"fmt"

	"github.com/hupe1980/awsrecon/pkg/common"
)

type AccessLevel string

const (
	AccessLevelWrite                 AccessLevel = "Write"
	AccessLevelRead                  AccessLevel = "Read"
	AccessLevelTagging               AccessLevel = "Tagging"
	AccessLevelPermissionsManagement AccessLevel = "Permissions management"
	AccessLevelList                  AccessLevel = "List"
)

type GetActionsInput struct {
	ServicePrefix    string
	AccessLevel      AccessLevel
	ResourceTypeName string // * => wildcard arns only
	NamePattern      string // supports wildcards: '*', '?'
}

func (d *Definitions) GetActions(input *GetActionsInput) []Action {
	actions := []Action{}

	prefixes := []string{input.ServicePrefix}
	if input.ServicePrefix == "" {
		prefixes = common.MapKeys(d.definitions)
	}

	for _, servicePrefix := range prefixes {
		if sd, ok := d.definitions[servicePrefix]; ok {
			for _, action := range sd.Actions {
				if input.AccessLevel != "" && string(input.AccessLevel) != action.AccessLevel {
					continue
				}

				if input.NamePattern != "" && !common.WildcardMatch(input.NamePattern, action.Name) {
					continue
				}

				if input.ResourceTypeName != "" {
					typeName := input.ResourceTypeName
					if typeName == "*" {
						if len(action.ResourceTypes) == 1 {
							// action does not support restricting to resource ARNs.
							typeName = ""
						} else {
							continue
						}
					}

					names := common.MapKeys(action.ResourceTypes)
					if !common.SliceContains(names, typeName) {
						continue
					}
				}

				actions = append(actions, Action(fmt.Sprintf("%s:%s", servicePrefix, action.Name)))
			}
		}
	}

	return actions
}

type ActionData struct {
	Name              string
	Description       string
	AccessLevel       string
	ResourceARNFormat string
	APIDocLink        string
	ConditionKeys     []string
	DependentActions  []string
}

// GetActionData gets details about an IAM Action
func (d *Definitions) GetActionData(action Action) []*ActionData {
	if sd, ok := d.definitions[action.ServicePrefix()]; ok {
		if action, ok := sd.Actions[action.Name()]; ok {
			var results []*ActionData

			resourceARNFormat := "*"
			conditionKeys := []string{}
			dependentActions := []string{}

			for _, art := range action.ResourceTypes {
				dependentActions = append(dependentActions, art.DependentActions...)

				if art.Name != "" {
					if srt, ok := sd.ResourceTypes[art.Name]; ok {
						resourceARNFormat = srt.ARN
						conditionKeys = srt.Conditions
					}
				}

				results = append(results, &ActionData{
					Name:              action.Name,
					Description:       action.Description,
					AccessLevel:       action.AccessLevel,
					ResourceARNFormat: resourceARNFormat,
					APIDocLink:        action.APIDocLink,
					ConditionKeys:     conditionKeys,
					DependentActions:  dependentActions,
				})
			}

			return results
		}
	}

	return nil
}
