package recon

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type Function struct {
	AWSService string
	Region     string
	Name       string
	Runtime    string
	Hints      []string
}

type FunctionsOptions struct {
	Names        []string
	BeforeHook   BeforeHookFunc
	AfterRunHook AfterRunHookFunc
}

type FunctionsRecon struct {
	*recon[Function]
	lambdaClient *lambda.Client
	opts         FunctionsOptions
}

func NewFunctionsRecon(cfg *config.Config, optFns ...func(o *FunctionsOptions)) *FunctionsRecon {
	opts := FunctionsOptions{}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &FunctionsRecon{
		lambdaClient: lambda.NewFromConfig(cfg.AWSConfig),
		opts:         opts,
	}

	r.recon = newRecon[Function](func() {
		r.runEnumerateServicePerRegion("lambda", cfg.Regions, func(region string) {
			r.enumerateFunctionsPerRegion(region)
		})
	}, func(o *reconOptions) {
		o.BeforeHook = opts.BeforeHook
		o.AfterRunHook = opts.AfterRunHook
	})

	return r
}

func (rec *FunctionsRecon) enumerateFunctionsPerRegion(region string) {
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
			var hints []string

			if isRuntimeEOL(function.Runtime) {
				hints = append(hints, "EOL")
			}

			rec.addResult(Function{
				AWSService: "Lambda",
				Region:     region,
				Name:       aws.ToString(function.FunctionName),
				Runtime:    string(function.Runtime),
				Hints:      hints,
			})
		}
	}
}

func isRuntimeEOL(r lambdaTypes.Runtime) bool {
	// nolint exhaustive not relevant
	switch r {
	case lambdaTypes.RuntimePython27, lambdaTypes.RuntimePython36:
		return true
	case lambdaTypes.RuntimeNodejs12x, lambdaTypes.RuntimeNodejs10x, lambdaTypes.RuntimeNodejs810, lambdaTypes.RuntimeNodejs610, lambdaTypes.RuntimeNodejs43:
		return true
	case lambdaTypes.RuntimeRuby25:
		return true
	}

	return false
}
