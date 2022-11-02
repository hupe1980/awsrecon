package recon

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codecommit"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type Repo struct {
	AWSService   string
	Region       string
	Name         string
	CloneURLHTTP string
}

type ReposOptions struct {
	Entropy              float64
	Verify               bool
	HighEntropyThreshold float64
}

type ReposRecon struct {
	*recon[Repo]
	codecommitClient *codecommit.Client
	stsClient        *sts.Client
	opts             ReposOptions
}

func NewReposRecon(cfg *config.Config, optFns ...func(o *ReposOptions)) *ReposRecon {
	opts := ReposOptions{
		Entropy:              0,
		Verify:               false,
		HighEntropyThreshold: 3.5,
	}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &ReposRecon{
		codecommitClient: codecommit.NewFromConfig(cfg.AWSConfig),
		stsClient:        sts.NewFromConfig(cfg.AWSConfig),
		opts:             opts,
	}

	r.recon = newRecon[Repo](func() {
		r.runEnumeratePerRegion(cfg.Regions, func(region string) {
			r.enumerateReposPerRegion(region)
		})
	})

	return r
}

func (rec *ReposRecon) enumerateReposPerRegion(region string) {
	p := codecommit.NewListRepositoriesPaginator(rec.codecommitClient, &codecommit.ListRepositoriesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *codecommit.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.Repositories {
			repo, err := rec.codecommitClient.GetRepository(context.TODO(), &codecommit.GetRepositoryInput{
				RepositoryName: item.RepositoryName,
			}, func(o *codecommit.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			rec.addResult(Repo{
				AWSService:   "CodeCommit",
				Region:       region,
				Name:         aws.ToString(item.RepositoryName),
				CloneURLHTTP: aws.ToString(repo.RepositoryMetadata.CloneUrlHttp),
			})
		}
	}
}
