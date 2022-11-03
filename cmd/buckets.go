package cmd

import (
	"fmt"
	"strings"

	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type bucketsOptions struct {
	buckets []string
}

func newBucketsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &bucketsOptions{}
	cmd := &cobra.Command{
		Use:           "buckets",
		Short:         "Enumerate s3 buckets",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent, globalOpts.timeout)
			if err != nil {
				return err
			}

			recon := recon.NewBucketsRecon(cfg, func(o *recon.BucketsOptions) {
				o.Buckets = opts.buckets
			})

			buckets := recon.Run()

			output := output.New([]string{
				"Service",
				"Region",
				"Location",
				"Name",
				"Block\nPublic\nAcls",
				"Block\nPublic\nPolicy",
				"Ignore\nPublic\nAcls",
				"Restrict\nPublic\nBuckets",
				"Policy\nStatus",
				"ACL\nStatus",
				"SSE",
				"Website",
				"OAI",
				"MFA\nDelete",
				"Version\ning",
				"Hints",
			})

			for _, b := range buckets {
				pab := b.Audit.PublicAccessBlock()

				oai := "Unknown"
				if b.Audit.OAICount() != -1 {
					oai = fmt.Sprintf("%d", b.Audit.OAICount())
				}

				output.Add([]string{
					b.AWSService,
					b.Region,
					b.Audit.Location(),
					b.Name,
					pab.BlockPublicAcls,
					pab.BlockPublicPolicy,
					pab.IgnorePublicAcls,
					pab.RestrictPublicBuckets,
					b.Audit.PolicyStatus(),
					b.Audit.ACLStatus(),
					b.Audit.ServerSideEncryptionStatus(),
					b.Audit.WebsiteConfigurationStatus(),
					oai,
					b.Audit.MFADeleteStatus(),
					b.Audit.VersioningStatus(),
					strings.Join(b.Hints, ",\n"),
				})
			}

			if globalOpts.output != "" {
				return output.SaveAsCSV(globalOpts.output)
			}

			output.PrintTable()

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&opts.buckets, "bucket", "b", nil, "bucket name")

	return cmd
}
