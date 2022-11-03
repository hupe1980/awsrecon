package cmd

import (
	"strings"

	"github.com/hupe1980/awsrecon/pkg/common"
	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type instancesOptions struct {
	verify               bool
	highEntropyThreshold float64
}

func newInstancesCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &instancesOptions{}
	cmd := &cobra.Command{
		Use:           "instances",
		Short:         "Enumerate ec2 instances",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent, globalOpts.timeout)
			if err != nil {
				return err
			}

			recon := recon.NewInstancesRecon(cfg, func(o *recon.InstancesOptions) {
				o.Verify = opts.verify
				o.HighEntropyThreshold = opts.highEntropyThreshold
			})

			instances := recon.Run()

			output := output.NewTable([]string{
				"Service",
				"Region",
				"Name",
				"State",
				"Platform",
				"Arch",
				"Type",
				//"VPC",
				"AZ",
				"PublicIP",
				"OpenPorts\n(Ingress)",
				"OpenPorts\n(Egress)",
				"PrivateIP",
				"Profile",
				"UserData",
				"IMDS",
				"Hints",
			})

			for _, instance := range instances {
				name := common.InsertStringEveryNth(instance.Name, "\n", 20)

				output.Add([]string{
					instance.AWSService,
					instance.Region,
					name,
					instance.State,
					instance.Platform,
					instance.Architecture,
					instance.InstanceType,
					//instance.VPCID,
					instance.AvailabilityZone,
					instance.PublicIP,
					strings.Join(instance.SGAudit.OpenFromAnywhereIngressPorts(), "\n"),
					strings.Join(instance.SGAudit.OpenToAnywhereEgressPorts(), "\n"),
					instance.PrivateIP,
					instance.InstanceProfile,
					instance.UserDataState,
					string(instance.IMDS),
					strings.Join(instance.Hints, "\n"),
				})
			}

			output.Print()

			return nil
		},
	}

	cmd.Flags().BoolVarP(&opts.verify, "verify", "", false, "verify secrets")
	cmd.Flags().Float64VarP(&opts.highEntropyThreshold, "high-entropy-threshold", "", 3.5, "high entropy threshold")

	return cmd
}
