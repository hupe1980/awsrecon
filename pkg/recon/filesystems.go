package recon

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type FileSystem struct {
	AWSService string
	Region     string
	Name       string
	Hints      []string
}

type FileSystemsOptions struct {
	IgnoreServices []string
	BeforeHook     BeforeHookFunc
	AfterRunHook   AfterRunHookFunc
}

type FileSystemsRecon struct {
	*recon[FileSystem]
	efsClient *efs.Client
	fsxClient *fsx.Client
	opts      FileSystemsOptions
}

func NewFileSystemsRecon(cfg *config.Config, optFns ...func(o *FileSystemsOptions)) *FileSystemsRecon {
	opts := FileSystemsOptions{}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &FileSystemsRecon{
		efsClient: efs.NewFromConfig(cfg.AWSConfig),
		fsxClient: fsx.NewFromConfig(cfg.AWSConfig),
		opts:      opts,
	}

	r.recon = newRecon[FileSystem](func() {
		r.runEnumerateServicePerRegion("efs", cfg.Regions, func(region string) {
			r.enumerateEFSFileSystemsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("fsx", cfg.Regions, func(region string) {
			r.enumerateFSXFileSystemsPerRegion(region)
		})
	}, func(o *reconOptions) {
		o.IgnoreServices = opts.IgnoreServices
		o.BeforeHook = opts.BeforeHook
		o.AfterRunHook = opts.AfterRunHook
	})

	return r
}

func (rec *FileSystemsRecon) enumerateEFSFileSystemsPerRegion(region string) {
	p := efs.NewDescribeFileSystemsPaginator(rec.efsClient, &efs.DescribeFileSystemsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *efs.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, fs := range page.FileSystems {
			var hints []string

			if fs.Encrypted != nil && aws.ToBool(fs.Encrypted) {
				hints = append(hints, "Encrypted")
			} else {
				hints = append(hints, "NotEncrypted")
			}

			rec.addResult(FileSystem{
				AWSService: "EFS",
				Region:     region,
				Name:       aws.ToString(fs.Name),
				Hints:      hints,
			})
		}
	}
}

func (rec *FileSystemsRecon) enumerateFSXFileSystemsPerRegion(region string) {
	p := fsx.NewDescribeFileSystemsPaginator(rec.fsxClient, &fsx.DescribeFileSystemsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *fsx.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, fs := range page.FileSystems {
			var name string

			for _, tag := range fs.Tags {
				if aws.ToString(tag.Key) == "Name" {
					name = aws.ToString(tag.Value)
				}
			}

			var hints []string

			rec.addResult(FileSystem{
				AWSService: "FSX",
				Region:     region,
				Name:       name,
				Hints:      hints,
			})
		}
	}
}
