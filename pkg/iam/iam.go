package iam

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

type Principal string

type Action string

func (a Action) ServicePrefix() string {
	return strings.Split(string(a), ":")[0]
}

func (a Action) Name() string {
	return strings.Split(string(a), ":")[1]
}

func (a Action) HasWildcard() bool {
	return strings.Contains(string(a), "*")
}

type Resource string

type Statement struct {
	Sid          string                   `json:"Sid,omitempty"`          // statement ID, service specific
	Effect       Effect                   `json:"Effect"`                 // Allow or Deny
	Principal    PricipalValue[Principal] `json:"Principal,omitempty"`    // principal that is allowed or denied
	NotPrincipal PricipalValue[Principal] `json:"NotPrincipal,omitempty"` // exception to a list of principals
	Action       StatementValue[Action]   `json:"Action"`                 // allowed or denied action
	NotAction    StatementValue[Action]   `json:"NotAction,omitempty"`    // matches everything except
	Resource     StatementValue[Resource] `json:"Resource,omitempty"`     // object or objects that the statement covers
	NotResource  StatementValue[Resource] `json:"NotResource,omitempty"`  // matches everything except
	Condition    json.RawMessage          `json:"Condition,omitempty"`    // conditions for when a policy is in effect
}

type PolicyDocument struct {
	ID         string      `json:"Id,omitempty"`
	Version    string      `json:"Version"`
	Statements []Statement `json:"Statement"`
}

// AWS allows string or []string as value, we convert everything to []T to avoid casting
type StatementValue[T ~string] []T

func (value *StatementValue[T]) UnmarshalJSON(b []byte) error {
	var raw interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	var p []T
	//  value can be string or []string, convert everything to []T
	switch v := raw.(type) {
	case string:
		p = []T{T(v)}
	case []interface{}:
		var items []T
		for _, item := range v {
			items = append(items, T(fmt.Sprintf("%v", item)))
		}

		p = items
	default:
		return fmt.Errorf("invalid %s statement value element: only string or []string are allowed", value)
	}

	*value = p

	return nil
}

type PricipalValue[T ~string] map[string][]T

func (value *PricipalValue[T]) UnmarshalJSON(b []byte) error {
	var raw interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	p := make(map[string][]T)

	switch v := raw.(type) {
	case string:
		// "Principal": "*" and  Principal" : { "AWS" : "*" } are equivalent
		p["AWS"] = []T{T(v)}
	case map[string]interface{}:
		for k, v := range v {
			switch vv := v.(type) {
			case string:
				p[k] = []T{T(fmt.Sprintf("%v", vv))}
			case []interface{}:
				var items []T
				for _, item := range vv {
					items = append(items, T(fmt.Sprintf("%v", item)))
				}

				p[k] = items
			default:
				return fmt.Errorf("invalid %s principal subvalue element: only string or []string are allowed", value)
			}
		}
	default:
		return fmt.Errorf("invalid %s principal value element: only string or map[string]string are allowed", value)
	}

	*value = p

	return nil
}

func ConvertToPolicyDocument(encoded string) (*PolicyDocument, error) {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil, err
	}

	var doc PolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

type ExternalIDCondition struct {
	StringEquals struct {
		StsExternalID string `json:"sts:ExternalId"`
	} `json:"StringEquals"`
}

func ConvertToExternalIDCondition(rawCondition []byte) (*ExternalIDCondition, error) {
	var eIDCond ExternalIDCondition
	if err := json.Unmarshal(rawCondition, &eIDCond); err != nil {
		return nil, err
	}

	return &eIDCond, nil
}
