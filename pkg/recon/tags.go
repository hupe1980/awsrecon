package recon

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/hupe1980/awsrecon/pkg/audit"
	"github.com/hupe1980/awsrecon/pkg/audit/secret"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type Tag struct {
	AWSService string
	Region     string
	ARN        string
	Name       string
	Type       string
	Key        string
	Value      string
	Entropy    float64
	Hints      []string
}

type TagsOptions struct {
	Entropy              float64
	Verify               bool
	HighEntropyThreshold float64
}

type TagsRecon struct {
	*recon[Tag]
	tagClient *resourcegroupstaggingapi.Client
	engine    *secret.Engine
	opts      TagsOptions
}

func NewTagsRecon(cfg *config.Config, optFns ...func(o *TagsOptions)) *TagsRecon {
	opts := TagsOptions{
		Entropy:              0,
		Verify:               false,
		HighEntropyThreshold: 3.5,
	}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &TagsRecon{
		tagClient: resourcegroupstaggingapi.NewFromConfig(cfg.AWSConfig),
		engine:    secret.NewEngine(opts.Verify),
		opts:      opts,
	}

	r.recon = newRecon[Tag](func() {
		r.runEnumeratePerRegion(cfg.Regions, func(region string) {
			r.enumerateTagsPerRegion(region)
		})
	})

	return r
}

func (rec *TagsRecon) enumerateTagsPerRegion(region string) {
	p := resourcegroupstaggingapi.NewGetResourcesPaginator(rec.tagClient, &resourcegroupstaggingapi.GetResourcesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *resourcegroupstaggingapi.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, resource := range page.ResourceTagMappingList {
			resourceARN := aws.ToString(resource.ResourceARN)

			parsedARN, err := arn.Parse(resourceARN)
			if err != nil {
				rec.addError(err)
				continue
			}

			resourceType := "bucket"
			if parsedARN.Service != "s3" {
				resourceType = strings.Split(parsedARN.Resource, ":")[0]
				resourceType = strings.Split(resourceType, "/")[0]
			}

			for _, tag := range resource.Tags {
				value := aws.ToString(tag.Value)

				entropy := audit.ShannonEntropy(value)
				if entropy < rec.opts.Entropy {
					continue
				}

				hints := rec.getHints(value, entropy)

				rec.addResult(Tag{
					AWSService: parsedARN.Service,
					ARN:        resourceARN,
					Name:       parsedARN.Resource,
					Region:     region,
					Type:       resourceType,
					Key:        aws.ToString(tag.Key),
					Value:      value,
					Entropy:    entropy,
					Hints:      hints,
				})
			}
		}
	}
}

func (rec *TagsRecon) getHints(value string, entropy float64) []string {
	hints := rec.engine.Scan(value)

	if entropy > rec.opts.HighEntropyThreshold {
		hints = append(hints, "HighEntropy")
	}

	return hints
}
