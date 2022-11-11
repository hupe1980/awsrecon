package recon

import (
	"context"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cloudformationTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/hupe1980/awsrecon/pkg/audit"
	"github.com/hupe1980/awsrecon/pkg/audit/cfn"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type Parameter struct {
	Key           string
	Value         string
	ResolvedValue string
	Entropy       float64
	Hints         []string
}

type Output struct {
	Description string
	ExportName  string
	Key         string
	Value       string
	Entropy     float64
	Hints       []string
}

type Resource struct {
	Name  string
	Type  string
	Hints []string
}

type Stack struct {
	AWSService   string
	Region       string
	Name         string
	Role         string
	Outputs      []*Output
	Parameters   []*Parameter
	Resources    []*Resource
	TemplateBody string
}

type StacksOptions struct {
	Entropy                  float64
	Verify                   bool
	HighEntropyThreshold     float64
	IgnoreCDKAssetParameters bool
	BeforeHook               BeforeHookFunc
	AfterRunHook             AfterRunHookFunc
}

type StacksRecon struct {
	*recon[Stack]
	cloudformationClient *cloudformation.Client
	engine               *cfn.Engine
	opts                 StacksOptions
}

func NewStacksRecon(cfg *config.Config, optFns ...func(o *StacksOptions)) *StacksRecon {
	opts := StacksOptions{
		Entropy:                  0,
		Verify:                   false,
		HighEntropyThreshold:     3.5,
		IgnoreCDKAssetParameters: false,
	}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &StacksRecon{
		cloudformationClient: cloudformation.NewFromConfig(cfg.AWSConfig),
		engine:               cfn.NewEngine(opts.Verify),
		opts:                 opts,
	}

	r.recon = newRecon[Stack](func() {
		r.runEnumerateServicePerRegion("cloudformation", cfg.Regions, func(region string) {
			r.enumerateStacksPerRegion(region)
		})
	}, func(o *reconOptions) {
		o.BeforeHook = opts.BeforeHook
		o.AfterRunHook = opts.AfterRunHook
	})

	return r
}

func (rec *StacksRecon) enumerateStacksPerRegion(region string) {
	p := cloudformation.NewDescribeStacksPaginator(rec.cloudformationClient, &cloudformation.DescribeStacksInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *cloudformation.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, stack := range page.Stacks {
			template, err := rec.cloudformationClient.GetTemplate(context.TODO(), &cloudformation.GetTemplateInput{
				StackName:     stack.StackId,
				TemplateStage: cloudformationTypes.TemplateStageOriginal,
			}, func(o *cloudformation.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			templateBody := aws.ToString(template.TemplateBody)

			stackAudit, err := rec.engine.NewStackAudit(templateBody)
			if err != nil {
				rec.addError(err)
				continue
			}

			var params []*Parameter

			for _, p := range stack.Parameters {
				key := aws.ToString(p.ParameterKey)
				value := aws.ToString(p.ParameterValue)

				// Filter cdk asset parameters
				if rec.opts.IgnoreCDKAssetParameters && isCDKAssetParameter(key) {
					continue
				}

				entropy := audit.ShannonEntropy(value)

				if entropy < rec.opts.Entropy {
					continue
				}

				hints := stackAudit.ScanParameter(&cfn.ScanParameterInput{
					Key:   key,
					Value: value,
				})

				if entropy > rec.opts.HighEntropyThreshold {
					hints = append(hints, "HighEntropy")
				}

				params = append(params, &Parameter{
					Key:           key,
					Value:         value,
					ResolvedValue: aws.ToString(p.ResolvedValue),
					Entropy:       entropy,
					Hints:         hints,
				})
			}

			var resources []*Resource

			for _, r := range stackAudit.ScanResources() {
				resources = append(resources, &Resource{
					Name:  r.Name,
					Type:  r.Type,
					Hints: r.Findings,
				})
			}

			var outputs []*Output

			for _, o := range stack.Outputs {
				key := aws.ToString(o.OutputKey)
				value := aws.ToString(o.OutputValue)

				entropy := audit.ShannonEntropy(value)

				if entropy < rec.opts.Entropy {
					continue
				}

				hints := stackAudit.ScanOutput(&cfn.ScanOutputInput{
					Key:   key,
					Value: value,
				})

				if entropy > rec.opts.HighEntropyThreshold {
					hints = append(hints, "HighEntropy")
				}

				outputs = append(outputs, &Output{
					Key:     key,
					Value:   value,
					Entropy: entropy,
					Hints:   hints,
				})
			}

			rec.addResult(Stack{
				AWSService:   "cloudformation",
				Name:         aws.ToString(stack.StackName),
				Region:       region,
				Role:         aws.ToString(stack.RoleARN),
				Outputs:      outputs,
				Parameters:   params,
				Resources:    resources,
				TemplateBody: templateBody,
			})
		}
	}
}

var cdkAssetParameterRegex = regexp.MustCompile(`^AssetParameters[a-z0-9]{64}(ArtifactHash|S3Bucket|S3VersionKey)[A-Z0-9]{8}$`)

func isCDKAssetParameter(value string) bool {
	return cdkAssetParameterRegex.Match([]byte(value))
}
