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
	names []string
}

func newBucketsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &bucketsOptions{}
	cmd := &cobra.Command{
		Use:           "buckets",
		Short:         "Enumerate s3 buckets",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewBucketsRecon(cfg, func(o *recon.BucketsOptions) {
				o.Names = opts.names
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			PrintInfof("Enumerating buckets for account %s", cfg.Account)

			buckets := recon.Run()

			progress.Wait()

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

			output.PrintTable()

			if globalOpts.output != "" {
				if err := output.SaveAsCSV(globalOpts.output); err != nil {
					return err
				}

				PrintInfof("Output written to %s", globalOpts.output)
			}

			PrintInfof("%d buckets enumerated.", len(buckets))

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&opts.names, "name", "n", nil, "bucket name")

	return cmd
}
