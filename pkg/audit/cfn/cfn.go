package cfn

import (
	"fmt"

	"github.com/hupe1980/awsrecon/pkg/audit/secret"
	"github.com/hupe1980/awsrecon/pkg/cloudformation"
)

type Engine struct {
	secretEngine *secret.Engine
	rules        []Rule
}

func NewEngine(verify bool) *Engine {
	return &Engine{
		secretEngine: secret.NewEngine(verify),
		rules: []Rule{
			CloudformationAuthenticationRule{},
			PasswordPropertyRule{},
		},
	}
}

type Audit struct {
	secretEngine *secret.Engine
	rules        []Rule
	template     *cloudformation.Template
}

func (e *Engine) NewStackAudit(templateBody string) (*Audit, error) {
	template, err := cloudformation.ParseYAMLString(templateBody)
	if err != nil {
		return nil, err
	}

	return &Audit{
		secretEngine: e.secretEngine,
		rules:        e.rules,
		template:     template,
	}, nil
}

type ScanParameterInput struct {
	Key           string
	Value         string
	ResolvedValue string
}

func (a *Audit) ScanParameter(input *ScanParameterInput) []string {
	findings := a.secretEngine.Scan(fmt.Sprintf("%s=%s", input.Key, input.Value))

	if p, ok := a.template.Parameters[input.Key]; ok {
		if p.NoEcho && p.Default != "" {
			findings = append(findings, "NoEchoWithDefault")
		}
	}

	return findings
}

type ScanOutputInput struct {
	Key   string
	Value string
}

func (a *Audit) ScanOutput(input *ScanOutputInput) []string {
	return a.secretEngine.Scan(fmt.Sprintf("%s=%s", input.Key, input.Value))
}

type ScanResourcesOutput struct {
	Name     string
	Type     string
	Findings []string
}

func (a *Audit) ScanResources() []*ScanResourcesOutput {
	output := []*ScanResourcesOutput{}

	for k, v := range a.template.Resources {
		findings := []string{}

		for _, rule := range a.rules {
			results, err := rule.Audit(v)
			if err != nil {
				print(err.Error())
				continue
			}

			for _, result := range results {
				findings = append(findings, result.ID)
			}
		}

		if len(findings) > 0 {
			output = append(output, &ScanResourcesOutput{
				Name:     k,
				Type:     v.Type,
				Findings: findings,
			})
		}
	}

	return output
}
