package recon

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/hupe1980/awsrecon/pkg/audit/bucket"
	"github.com/hupe1980/awsrecon/pkg/common"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type Bucket struct {
	AWSService   string
	Region       string
	Name         string
	CreationDate time.Time
	Audit        *bucket.Audit
	Hints        []string
}

type BucketsOptions struct {
	Buckets []string
}

type BucketsRecon struct {
	*recon[Bucket]
	s3Client *s3.Client
	opts     BucketsOptions
}

func NewBucketsRecon(cfg *config.Config, optFns ...func(o *BucketsOptions)) *BucketsRecon {
	opts := BucketsOptions{}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &BucketsRecon{
		s3Client: s3.NewFromConfig(cfg.AWSConfig),
		opts:     opts,
	}

	r.recon = newRecon[Bucket](func() {
		r.runEnumerate(func() {
			r.enumerateBuckets()
		})
	})

	return r
}

func (rec *BucketsRecon) enumerateBuckets() {
	list, err := rec.s3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		rec.addError(err)
		return
	}

	for _, item := range list.Buckets {
		if len(rec.opts.Buckets) > 0 {
			if !common.SliceContains(rec.opts.Buckets, aws.ToString(item.Name)) {
				continue
			}
		}

		rec.wgAdd(1)

		go func(b s3Types.Bucket) {
			defer rec.wgDone()

			audit := bucket.NewAudit(rec.s3Client, b.Name)

			var hints []string
			if audit.IsPublic() {
				hints = append(hints, "Public")
			}

			rec.addResult(Bucket{
				AWSService:   "S3",
				Name:         aws.ToString(b.Name),
				Region:       "global",
				CreationDate: aws.ToTime(b.CreationDate),
				Audit:        audit,
				Hints:        hints,
			})
		}(item)
	}
}
