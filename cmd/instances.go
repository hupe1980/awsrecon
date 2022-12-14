package cmd

import (
	"net"
	"strings"

	"github.com/hupe1980/awsrecon/pkg/common"
	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type instancesOptions struct {
	instanceStates       []string
	verify               bool
	highEntropyThreshold float64
	myIP                 net.IP
}

func newInstancesCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &instancesOptions{}
	cmd := &cobra.Command{
		Use:           "instances",
		Short:         "Enumerate ec2 instances",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewInstancesRecon(cfg, func(o *recon.InstancesOptions) {
				o.InstanceStates = opts.instanceStates
				o.Verify = opts.verify
				o.HighEntropyThreshold = opts.highEntropyThreshold
				o.MyIP = opts.myIP
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			PrintInfof("Enumerating instances for account %s", cfg.Account)

			instances := recon.Run()

			progress.Wait()

			output := output.New([]string{
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
				"PrivateIP",
				"OpenPorts\n(Ingress)",
				"OpenPorts\n(Egress)",
				"Profile",
				"UserData",
				"IMDS",
				"Hints",
			})

			for _, instance := range instances {
				if instance.Name == "" {
					// Fallback if the instance has no name tag
					instance.Name = instance.ID
				}

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
					instance.PrivateIP,
					strings.Join(common.MapKeys(instance.SGAudit.OpenIngressPorts()), ",\n"),
					strings.Join(common.MapKeys(instance.SGAudit.OpenEgressPorts()), ",\n"),
					instance.InstanceProfile,
					instance.UserDataState,
					string(instance.IMDS),
					strings.Join(instance.Hints, ",\n"),
				})
			}

			output.PrintTable()

			if globalOpts.output != "" {
				if err := output.SaveAsCSV(globalOpts.output); err != nil {
					return err
				}

				PrintInfof("Output written to %s", globalOpts.output)
			}

			PrintInfof("%d instances enumerated.", len(instances))

			return nil
		},
	}

	cmd.PersistentFlags().StringSliceVarP(&opts.instanceStates, "states", "s", nil, "instance states (default all states)")
	cmd.Flags().BoolVarP(&opts.verify, "verify", "", false, "verify secrets")
	cmd.Flags().Float64VarP(&opts.highEntropyThreshold, "high-entropy-threshold", "", 3.5, "high entropy threshold")
	cmd.Flags().IPVarP(&opts.myIP, "my-ip", "", nil, "ip to check open ports")

	return cmd
}
