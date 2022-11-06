package config

import (
	"context"
	"time"

	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	DefaultUserAgent = "awsrecon"
)

// AWSRegions from https://docs.aws.amazon.com/de_de/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-regions
var AWSRegions = []string{"us-east-1", "us-east-2", "us-west-1", "us-west-2", "af-south-1", "ap-east-1", "ap-south-1", "ap-northeast-3", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1", "eu-west-3", "eu-north-1", "me-south-1", "sa-east-1"}

type Config struct {
	// The Amazon Web Services account ID number of the account that owns or contains the calling entity
	Account string

	// The SharedConfigProfile that is used
	Profile string

	// The regions to send requests to.
	Regions []string

	// The request timeout limit
	Timeout time.Duration

	// A Config provides service configuration for aws service clients
	AWSConfig aws.Config
}

func NewConfig(profile string, regions []string, userAgent string, timeout time.Duration) (*Config, error) {
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}

	if regions == nil {
		regions = AWSRegions
	}

	awsCfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion("us-east-1"),
		config.WithSharedConfigProfile(profile),
		config.WithAssumeRoleCredentialOptions(func(aro *stscreds.AssumeRoleOptions) {
			aro.TokenProvider = stscreds.StdinTokenProvider
		}),
		config.WithRetryer(func() aws.Retryer {
			return retry.AddWithMaxAttempts(retry.NewStandard(), 5)
		}),
		config.WithAPIOptions([]func(*smithymiddleware.Stack) error{
			smithyhttp.SetHeaderValue("User-Agent", userAgent),
		}),
		//config.WithClientLogMode(aws.LogRequestWithBody),
	)
	if err != nil {
		return nil, err
	}

	client := sts.NewFromConfig(awsCfg)

	output, err := client.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}

	return &Config{
		Account:   *output.Account,
		Profile:   profile,
		Regions:   regions,
		Timeout:   timeout,
		AWSConfig: awsCfg,
	}, nil
}
