package recon

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/hupe1980/awsrecon/pkg/audit"
	"github.com/hupe1980/awsrecon/pkg/audit/secret"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type Secret struct {
	AWSService  string
	Region      string
	Name        string
	Description string
	Type        string
	Value       string
	Entropy     float64
	Hints       []string
}

type SecretsOptions struct {
	Entropy              float64
	WithDecryption       bool
	Verify               bool
	HighEntropyThreshold float64
}

type SecretsRecon struct {
	*recon[Secret]
	secretsManagerClient *secretsmanager.Client
	ssmClient            *ssm.Client
	engine               *secret.Engine
	opts                 SecretsOptions
}

func NewSecretsRecon(cfg *config.Config, optFns ...func(o *SecretsOptions)) *SecretsRecon {
	opts := SecretsOptions{
		Entropy:              0,
		WithDecryption:       false,
		Verify:               false,
		HighEntropyThreshold: 3.5,
	}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &SecretsRecon{
		secretsManagerClient: secretsmanager.NewFromConfig(cfg.AWSConfig),
		ssmClient:            ssm.NewFromConfig(cfg.AWSConfig),
		engine:               secret.NewEngine(opts.Verify),
		opts:                 opts,
	}

	r.recon = newRecon[Secret](func() {
		r.runEnumeratePerRegion(cfg.Regions, func(region string) {
			r.enumerateSecretManagerSecretsPerRegion(region)
		})

		r.runEnumeratePerRegion(cfg.Regions, func(region string) {
			r.enumerateSSMSecretsPerRegion(region)
		})
	})

	return r
}

func (rec *SecretsRecon) enumerateSecretManagerSecretsPerRegion(region string) {
	p := secretsmanager.NewListSecretsPaginator(rec.secretsManagerClient, &secretsmanager.ListSecretsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *secretsmanager.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, entry := range page.SecretList {
			var description string
			if entry.Description != nil {
				description = aws.ToString(entry.Description)
			}

			var (
				value   string
				entropy float64
				hints   []string
			)

			value = "[ENCRYPTED]"

			if rec.opts.WithDecryption {
				output, err := rec.secretsManagerClient.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
					SecretId: entry.ARN,
				}, func(o *secretsmanager.Options) {
					o.Region = region
				})
				if err != nil {
					rec.addError(err)
					continue
				}

				if output.SecretBinary != nil {
					value = "[Binary]"
				} else {
					value = aws.ToString(output.SecretString)
					entropy = audit.ShannonEntropy(value)
					hints = rec.getHints(value, entropy)
				}
			}

			rec.addResult(Secret{
				AWSService:  "SecretsManager",
				Region:      region,
				Name:        aws.ToString(entry.Name),
				Description: description,
				Type:        "SecureString",
				Value:       value,
				Entropy:     entropy,
				Hints:       hints,
			})
		}
	}
}

func (rec *SecretsRecon) enumerateSSMSecretsPerRegion(region string) {
	p := ssm.NewDescribeParametersPaginator(rec.ssmClient, &ssm.DescribeParametersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *ssm.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, parameter := range page.Parameters {
			var description string
			if parameter.Description != nil {
				description = aws.ToString(parameter.Description)
			}

			output, err := rec.ssmClient.GetParameter(context.TODO(), &ssm.GetParameterInput{
				Name:           parameter.Name,
				WithDecryption: &rec.opts.WithDecryption,
			}, func(o *ssm.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			var (
				value   string
				entropy float64
				hints   []string
			)

			if output.Parameter.Value != nil {
				if !rec.opts.WithDecryption && parameter.Type == ssmTypes.ParameterTypeSecureString {
					value = "[ENCRYPTED]"
				} else {
					value = aws.ToString(output.Parameter.Value)
					entropy = audit.ShannonEntropy(value)
					hints = rec.getHints(value, entropy)
				}
			}

			if entropy < rec.opts.Entropy {
				continue
			}

			rec.addResult(Secret{
				AWSService:  "SSM",
				Region:      region,
				Name:        aws.ToString(parameter.Name),
				Description: description,
				Type:        string(parameter.Type),
				Value:       value,
				Entropy:     entropy,
				Hints:       hints,
			})
		}
	}
}

func (rec *SecretsRecon) getHints(value string, entropy float64) []string {
	hints := rec.engine.Scan(value)

	if entropy > rec.opts.HighEntropyThreshold {
		hints = append(hints, "HighEntropy")
	}

	return hints
}
