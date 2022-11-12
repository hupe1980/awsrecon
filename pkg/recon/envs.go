package recon

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildTypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
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
	BeforeHook           BeforeHookFunc
	AfterRunHook         AfterRunHookFunc
}

type EnvsRecon struct {
	*recon[Env]
	apprunnerClient *apprunner.Client
	codebuildClient *codebuild.Client
	ecsClient       *ecs.Client
	lambdaClient    *lambda.Client
	sagemakerClient *sagemaker.Client
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
		apprunnerClient: apprunner.NewFromConfig(cfg.AWSConfig),
		codebuildClient: codebuild.NewFromConfig(cfg.AWSConfig),
		ecsClient:       ecs.NewFromConfig(cfg.AWSConfig),
		lambdaClient:    lambda.NewFromConfig(cfg.AWSConfig),
		sagemakerClient: sagemaker.NewFromConfig(cfg.AWSConfig),
		engine:          secret.NewEngine(opts.Verify),
		opts:            opts,
	}

	r.recon = newRecon[Env](func() {
		r.runEnumerateServicePerRegion("apprunner", cfg.Regions, func(region string) {
			r.enumerateApprunnerEnvsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("codebuild", cfg.Regions, func(region string) {
			r.enumerateCodebuildEnvsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("ecs", cfg.Regions, func(region string) {
			r.enumerateECSEnvsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("lambda", cfg.Regions, func(region string) {
			r.enumerateLambdaEnvsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("sagemaker-processing", cfg.Regions, func(region string) {
			r.enumerateSagemakerProcessingJobEnvsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("sagemaker-transform", cfg.Regions, func(region string) {
			r.enumerateSagemakerTransformJobEnvsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("sagemaker-training", cfg.Regions, func(region string) {
			r.enumerateSagemakerTrainingJobEnvsPerRegion(region)
		})
	}, func(o *reconOptions) {
		o.IgnoreServices = opts.IgnoreServices
		o.BeforeHook = opts.BeforeHook
		o.AfterRunHook = opts.AfterRunHook
	})

	return r
}

func (rec *EnvsRecon) enumerateApprunnerEnvsPerRegion(region string) {
	p := apprunner.NewListServicesPaginator(rec.apprunnerClient, &apprunner.ListServicesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *apprunner.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.ServiceSummaryList {
			output, err := rec.apprunnerClient.DescribeService(context.TODO(), &apprunner.DescribeServiceInput{
				ServiceArn: item.ServiceArn,
			}, func(o *apprunner.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			if len(output.Service.SourceConfiguration.ImageRepository.ImageConfiguration.RuntimeEnvironmentVariables) > 0 {
				for key, value := range output.Service.SourceConfiguration.ImageRepository.ImageConfiguration.RuntimeEnvironmentVariables {
					entropy := audit.ShannonEntropy(value)

					if entropy < rec.opts.Entropy {
						continue
					}

					hints := rec.getHints(fmt.Sprintf("%s=%s", key, value), entropy)

					rec.addResult(Env{
						AWSService: "Apprunner",
						Name:       aws.ToString(output.Service.ServiceName),
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

func (rec *EnvsRecon) enumerateSagemakerProcessingJobEnvsPerRegion(region string) {
	p := sagemaker.NewListProcessingJobsPaginator(rec.sagemakerClient, &sagemaker.ListProcessingJobsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *sagemaker.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.ProcessingJobSummaries {
			output, err := rec.sagemakerClient.DescribeProcessingJob(context.TODO(), &sagemaker.DescribeProcessingJobInput{
				ProcessingJobName: item.ProcessingJobName,
			}, func(o *sagemaker.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			if len(output.Environment) > 0 {
				for key, value := range output.Environment {
					name := fmt.Sprintf("[Processing Job] %s", aws.ToString(output.ProcessingJobName))

					entropy := audit.ShannonEntropy(value)

					if entropy < rec.opts.Entropy {
						continue
					}

					hints := rec.getHints(fmt.Sprintf("%s=%s", key, value), entropy)

					rec.addResult(Env{
						AWSService: "Sagemaker",
						Name:       name,
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

func (rec *EnvsRecon) enumerateSagemakerTransformJobEnvsPerRegion(region string) {
	p := sagemaker.NewListTransformJobsPaginator(rec.sagemakerClient, &sagemaker.ListTransformJobsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *sagemaker.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.TransformJobSummaries {
			output, err := rec.sagemakerClient.DescribeTransformJob(context.TODO(), &sagemaker.DescribeTransformJobInput{
				TransformJobName: item.TransformJobName,
			}, func(o *sagemaker.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			if len(output.Environment) > 0 {
				for key, value := range output.Environment {
					name := fmt.Sprintf("[Transform Job] %s", aws.ToString(output.TransformJobName))

					entropy := audit.ShannonEntropy(value)

					if entropy < rec.opts.Entropy {
						continue
					}

					hints := rec.getHints(fmt.Sprintf("%s=%s", key, value), entropy)

					rec.addResult(Env{
						AWSService: "Sagemaker",
						Name:       name,
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

func (rec *EnvsRecon) enumerateSagemakerTrainingJobEnvsPerRegion(region string) {
	p := sagemaker.NewListTrainingJobsPaginator(rec.sagemakerClient, &sagemaker.ListTrainingJobsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *sagemaker.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.TrainingJobSummaries {
			output, err := rec.sagemakerClient.DescribeTrainingJob(context.TODO(), &sagemaker.DescribeTrainingJobInput{
				TrainingJobName: item.TrainingJobName,
			}, func(o *sagemaker.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			if len(output.Environment) > 0 {
				for key, value := range output.Environment {
					name := fmt.Sprintf("[Training Job] %s", aws.ToString(output.TrainingJobName))

					entropy := audit.ShannonEntropy(value)

					if entropy < rec.opts.Entropy {
						continue
					}

					hints := rec.getHints(fmt.Sprintf("%s=%s", key, value), entropy)

					rec.addResult(Env{
						AWSService: "Sagemaker",
						Name:       name,
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
