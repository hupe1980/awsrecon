package recon

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/hupe1980/awsrecon/pkg/common"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type AccessKey struct {
	AWSService string
	UserName   string
	ID         string
	CreateDate time.Time
	Status     string
}

type AccessKeysOptions struct {
	UserNames    []string
	IDs          []string
	BeforeHook   BeforeHookFunc
	AfterRunHook AfterRunHookFunc
}

type AccessKeysRecon struct {
	*recon[AccessKey]
	iamClient *iam.Client
	opts      AccessKeysOptions
}

func NewAccessKeysRecon(cfg *config.Config, optFns ...func(o *AccessKeysOptions)) *AccessKeysRecon {
	opts := AccessKeysOptions{}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &AccessKeysRecon{
		iamClient: iam.NewFromConfig(cfg.AWSConfig),
		opts:      opts,
	}

	r.recon = newRecon[AccessKey](func() {
		r.runEnumerateService("iam", func() {
			r.enumerateAccessKeys()
		})
	}, func(o *reconOptions) {
		o.BeforeHook = opts.BeforeHook
		o.AfterRunHook = opts.AfterRunHook
	})

	return r
}

func (rec *AccessKeysRecon) enumerateAccessKeys() {
	p := iam.NewListAccessKeysPaginator(rec.iamClient, &iam.ListAccessKeysInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO())
		if err != nil {
			rec.addError(err)
			return
		}

		for _, key := range page.AccessKeyMetadata {
			id := aws.ToString(key.AccessKeyId)
			name := aws.ToString(key.UserName)

			if len(rec.opts.IDs) > 0 && !common.SliceContains(rec.opts.IDs, id) {
				continue
			}

			if len(rec.opts.UserNames) > 0 && !common.SliceContains(rec.opts.UserNames, name) {
				continue
			}

			rec.addResult(AccessKey{
				AWSService: "IAM",
				UserName:   name,
				ID:         id,
				CreateDate: aws.ToTime(key.CreateDate),
				Status:     string(key.Status),
			})
		}
	}
}
