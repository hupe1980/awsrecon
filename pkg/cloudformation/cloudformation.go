package cloudformation

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Mapping matches a key to a corresponding set of named values. For example,
// if you want to set values based on a region, you can create a mapping that
// uses the region name as a key and contains the values you want to specify
// for each specific region. You use the Fn::FindInMap intrinsic function to
// retrieve values in a map.
//
// See http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/mappings-section-structure.html
type Mapping map[string]map[string]string

// Parameter represents a parameter to the template.
//
// You can use the optional Parameters section to pass values into your
// template when you create a stack. With parameters, you can create templates
// that are customized each time you create a stack. Each parameter must
// contain a value when you create a stack. You can specify a default value to
// make the parameter optional.
//
// See http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html
type Parameter struct {
	Type                  string   `yaml:"Type"`
	Default               string   `yaml:"Default"`
	NoEcho                bool     `yaml:"NoEcho"`
	AllowedValues         []string `yaml:"AllowedValues"`
	AllowedPattern        string   `yaml:"AllowedPattern"`
	MinLength             int64    `yaml:"MinLength"`
	MaxLength             int64    `yaml:"MaxLength"`
	MinValue              int64    `yaml:"MinValue"`
	MaxValue              int64    `yaml:"MaxValue"`
	Description           string   `yaml:"Description"`
	ConstraintDescription string   `yaml:"ConstraintDescription"`
}

// Resource represents a resource in a cloudformation template. It contains resource
// metadata and, in Properties, a struct that implements ResourceProperties which
// contains the properties of the resource.
//
// See https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resources-section-structure.html
type Resource struct {
	Type       string                 `yaml:"Type"`
	Properties map[string]interface{} `yaml:"Properties"`
	Metadata   map[string]interface{} `yaml:"Metadata"`
}

// OutputExport represents the name of the resource output that should
// be used for cross stack references.
//
// See http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/walkthrough-crossstackref.html
type OutputExport struct {
	Name string `yaml:"Name"`
}

// Output represents a template output
//
// The optional Outputs section declares output values that you want to view from the
// AWS CloudFormation console or that you want to return in response to describe stack calls.
// For example, you can output the Amazon S3 bucket name for a stack so that you can easily find it.
//
// See http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html
type Output struct {
	Description string        `yaml:"Description"`
	Value       interface{}   `yaml:"Value"`
	Export      *OutputExport `yaml:"Export"`
}

// Template represents a CloudFormation template.
type Template struct {
	AWSTemplateFormatVersion string                 `yaml:"AWSTemplateFormatVersion"`
	Description              string                 `yaml:"Description"`
	Mappings                 map[string]*Mapping    `yaml:"Mappings"`
	Parameters               map[string]*Parameter  `yaml:"Parameters"`
	Resources                map[string]*Resource   `yaml:"Resources"`
	Outputs                  map[string]*Output     `yaml:"Output"`
	Conditions               map[string]interface{} `yaml:"Conditions"`
}

func (t *Template) Stats() map[string]int {
	stats := make(map[string]int)

	for _, v := range t.Resources {
		if count, ok := stats[v.Type]; ok {
			stats[v.Type] = count + 1
		} else {
			stats[v.Type] = 1
		}
	}

	return stats
}

func ParseYAMLString(input string) (*Template, error) {
	var template Template

	if err := yaml.Unmarshal([]byte(input), &template); err != nil {
		return nil, fmt.Errorf("invalid YAML: %s", err)
	}

	return &template, nil
}
