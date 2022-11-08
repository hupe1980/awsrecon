package iam

import "github.com/hupe1980/awsrecon/pkg/common"

func (d *Definitions) ServicePrefixes() []string {
	return common.MapKeys(d.definitions)
}

func (d *Definitions) GetServiceDefinition(prefix string) *ServiceDefinition {
	if d, ok := d.definitions[prefix]; ok {
		return d
	}

	return nil
}
