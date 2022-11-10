package recon

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildTypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/hupe1980/awsrecon/pkg/audit"
	"github.com/hupe1980/awsrecon/pkg/audit/secret"
	"github.com/hupe1980/awsrecon/pkg/buildspec"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type Env struct {
	AWSService string
	Region     string
	Name       string
	Key        string
	Value      string
	Entropy    float64
	Hints      []string
}

type EnvsOptions struct {
	Entropy              float64
	Verify               bool
	HighEntropyThreshold float64
	IgnoreServices       []string
}

type EnvsRecon struct {
	*recon[Env]
	codebuildClient *codebuild.Client
	ecsClient       *ecs.Client
	lambdaClient    *lambda.Client
	engine          *secret.Engine
	opts            EnvsOptions
}

func NewEnvsRecon(cfg *config.Config, optFns ...func(o *EnvsOptions)) *EnvsRecon {
	opts := EnvsOptions{
		Entropy:              0,
		Verify:               false,
		HighEntropyThreshold: 3.5,
	}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &EnvsRecon{
		codebuildClient: codebuild.NewFromConfig(cfg.AWSConfig),
		ecsClient:       ecs.NewFromConfig(cfg.AWSConfig),
		lambdaClient:    lambda.NewFromConfig(cfg.AWSConfig),
		engine:          secret.NewEngine(opts.Verify),
		opts:            opts,
	}

	r.recon = newRecon[Env](func() {
		r.runEnumerateServicePerRegion("codebuild", cfg.Regions, func(region string) {
			r.enumerateCodebuildEnvsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("ecs", cfg.Regions, func(region string) {
			r.enumerateECSEnvsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("lambda", cfg.Regions, func(region string) {
			r.enumerateLambdaEnvsPerRegion(region)
		})
	})

	return r
}

func (rec *EnvsRecon) enumerateCodebuildEnvsPerRegion(region string) {
	p := codebuild.NewListProjectsPaginator(rec.codebuildClient, &codebuild.ListProjectsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *codebuild.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		output, err := rec.codebuildClient.BatchGetProjects(context.TODO(), &codebuild.BatchGetProjectsInput{
			Names: page.Projects,
		}, func(o *codebuild.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			continue
		}

		for _, project := range output.Projects {
			for _, env := range project.Environment.EnvironmentVariables {
				if env.Type == codebuildTypes.EnvironmentVariableTypePlaintext {
					key := aws.ToString(env.Name)
					value := aws.ToString(env.Value)

					entropy := audit.ShannonEntropy(value)

					if entropy < rec.opts.Entropy {
						continue
					}

					hints := rec.getHints(fmt.Sprintf("%s=%s", key, value), entropy)

					rec.addResult(Env{
						AWSService: "Codebuild",
						Name:       aws.ToString(project.Name),
						Region:     region,
						Key:        key,
						Value:      value,
						Entropy:    entropy,
						Hints:      hints,
					})
				}
			}

			// Check buildspec
			if project.Source.Buildspec != nil {
				buildspec, err := buildspec.ParseJSONString(aws.ToString(project.Source.Buildspec))
				if err != nil {
					rec.addError(err)
					continue
				}

				for k, v := range buildspec.Env.Variables {
					entropy := audit.ShannonEntropy(v)

					if entropy < rec.opts.Entropy {
						continue
					}

					hints := rec.getHints(fmt.Sprintf("%s=%s", k, v), entropy)

					rec.addResult(Env{
						AWSService: "Codebuild",
						Name:       aws.ToString(project.Name),
						Region:     region,
						Key:        k,
						Value:      v,
						Entropy:    entropy,
						Hints:      hints,
					})
				}
			}
		}
	}
}

func (rec *EnvsRecon) enumerateECSEnvsPerRegion(region string) {
	p := ecs.NewListTaskDefinitionsPaginator(rec.ecsClient, &ecs.ListTaskDefinitionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *ecs.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for i := range page.TaskDefinitionArns {
			output, err := rec.ecsClient.DescribeTaskDefinition(context.TODO(),
				&ecs.DescribeTaskDefinitionInput{
					TaskDefinition: &page.TaskDefinitionArns[i],
				}, func(o *ecs.Options) {
					o.Region = region
				},
			)
			if err != nil {
				rec.addError(err)
				continue
			}

			for _, containerDefinition := range output.TaskDefinition.ContainerDefinitions {
				if containerDefinition.Environment != nil {
					for _, env := range containerDefinition.Environment {
						key := aws.ToString(env.Name)
						value := aws.ToString(env.Value)

						entropy := audit.ShannonEntropy(value)

						if entropy < rec.opts.Entropy {
							continue
						}

						hints := rec.getHints(fmt.Sprintf("%s=%s", key, value), entropy)

						rec.addResult(Env{
							AWSService: "ECS",
							Name:       aws.ToString(containerDefinition.Name),
							Region:     region,
							Key:        key,
							Value:      value,
							Entropy:    entropy,
							Hints:      hints,
						})
					}
				}
			}
		}
	}
}

func (rec *EnvsRecon) enumerateLambdaEnvsPerRegion(region string) {
	p := lambda.NewListFunctionsPaginator(rec.lambdaClient, &lambda.ListFunctionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *lambda.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, function := range page.Functions {
			if function.Environment != nil {
				for key, value := range function.Environment.Variables {
					entropy := audit.ShannonEntropy(value)

					if entropy < rec.opts.Entropy {
						continue
					}

					hints := rec.getHints(fmt.Sprintf("%s=%s", key, value), entropy)

					rec.addResult(Env{
						AWSService: "Lambda",
						Name:       aws.ToString(function.FunctionName),
						Region:     region,
						Key:        key,
						Value:      value,
						Entropy:    entropy,
						Hints:      hints,
					})
				}
			}
		}
	}
}

func (rec *EnvsRecon) getHints(value string, entropy float64) []string {
	hints := rec.engine.Scan(value)

	if entropy > rec.opts.HighEntropyThreshold {
		hints = append(hints, "HighEntropy")
	}

	return hints
}
