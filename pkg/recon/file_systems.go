package recon

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxTypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
	"github.com/aws/smithy-go"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type FileSystem struct {
	AWSService string
	Region     string
	Name       string
	DNS        string
	IP         string
	Mount      string
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

			describeFileSystemPolicyOutput, err := rec.efsClient.DescribeFileSystemPolicy(context.TODO(), &efs.DescribeFileSystemPolicyInput{
				FileSystemId: fs.FileSystemId,
			})
			if err == nil && describeFileSystemPolicyOutput.Policy != nil {
				hints = append(hints, "IAMAuth")
			} else {
				var ae smithy.APIError
				if errors.As(err, &ae) && ae.ErrorCode() == "PolicyNotFound" {
					hints = append(hints, "NoIAMAuth")
				} else {
					rec.addError(err)
				}
			}

			var paginationControl *string

			for {
				output, err := rec.efsClient.DescribeMountTargets(context.TODO(), &efs.DescribeMountTargetsInput{
					FileSystemId: fs.FileSystemId,
					Marker:       paginationControl,
				}, func(o *efs.Options) {
					o.Region = region
				})
				if err != nil {
					rec.addError(err)
					break
				}

				dnsName := fmt.Sprintf("%s.efs.%s.amazonaws.com", aws.ToString(fs.FileSystemId), region)

				if fs.AvailabilityZoneName != nil { // One Zone storage class
					dnsName = fmt.Sprintf("%s.%s.efs.%s.amazonaws.com", aws.ToString(fs.AvailabilityZoneName), aws.ToString(fs.FileSystemId), region)

					hints = append(hints, "OneZoneStorageClass")
				}

				for _, mt := range output.MountTargets {
					rec.addResult(FileSystem{
						AWSService: "EFS",
						Region:     region,
						Name:       aws.ToString(fs.Name),
						DNS:        dnsName,
						IP:         aws.ToString(mt.IpAddress),
						Mount:      aws.ToString(mt.MountTargetId),
						Hints:      hints,
					})
				}

				if output.NextMarker != nil {
					paginationControl = output.NextMarker
				} else {
					break
				}
			}
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

			switch fs.FileSystemType {
			case fsxTypes.FileSystemTypeLustre:
				rec.addResult(FileSystem{
					AWSService: "FSx [Lustre]",
					Region:     region,
					Name:       name,
					DNS:        aws.ToString(fs.DNSName),
					IP:         "",
					Mount:      aws.ToString(fs.LustreConfiguration.MountName),
					Hints:      hints,
				})
			case fsxTypes.FileSystemTypeWindows:
				rec.addResult(FileSystem{
					AWSService: "FSx [Windows]",
					Region:     region,
					Name:       name,
					DNS:        aws.ToString(fs.DNSName),
					IP:         aws.ToString(fs.WindowsConfiguration.PreferredFileServerIp),
					Mount:      "",
					Hints:      hints,
				})
			case fsxTypes.FileSystemTypeOntap, fsxTypes.FileSystemTypeOpenzfs:
				vp := fsx.NewDescribeVolumesPaginator(rec.fsxClient, &fsx.DescribeVolumesInput{
					Filters: []fsxTypes.VolumeFilter{
						{
							Name:   "file-system-id",
							Values: []string{*fs.FileSystemId},
						},
					},
				})
				for vp.HasMorePages() {
					vPage, err := vp.NextPage(context.TODO(), func(o *fsx.Options) {
						o.Region = region
					})
					if err != nil {
						rec.addError(err)
						break
					}

					for _, volume := range vPage.Volumes {
						if fs.FileSystemType == fsxTypes.FileSystemTypeOpenzfs {
							rec.addResult(FileSystem{
								AWSService: "FSx [OpenZFS]",
								Region:     region,
								Name:       name,
								DNS:        aws.ToString(fs.DNSName),
								IP:         "",
								Mount:      aws.ToString(volume.OpenZFSConfiguration.VolumePath),
								Hints:      hints,
							})
						} else {
							rec.addResult(FileSystem{
								AWSService: "FSx [ONTAP]",
								Region:     region,
								Name:       name,
								DNS:        aws.ToString(fs.DNSName),
								IP:         "",
								Mount:      aws.ToString(volume.OntapConfiguration.JunctionPath),
								Hints:      hints,
							})
						}
					}
				}
			}
		}
	}
}
