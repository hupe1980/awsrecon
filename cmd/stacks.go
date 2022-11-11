package cmd

import (
	"fmt"
	"strings"

	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type stacksOptions struct {
	entropy                  float64
	verify                   bool
	highEntropyThreshold     float64
	ignoreCDKAssetParameters bool
}

func newStacksCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &stacksOptions{}
	cmd := &cobra.Command{
		Use:           "stacks",
		Short:         "Enumerate cloudformation stacks",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewStacksRecon(cfg, func(o *recon.StacksOptions) {
				o.Entropy = opts.entropy
				o.Verify = opts.verify
				o.HighEntropyThreshold = opts.highEntropyThreshold
				o.IgnoreCDKAssetParameters = opts.ignoreCDKAssetParameters
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			stacks := recon.Run()

			progress.Wait()

			output := output.New([]string{
				"Service",
				"Region",
				"Name",
				"Type",
				"Key",
				"Value",
				"Entropy",
				"Hints",
			})

			for _, stack := range stacks {
				for _, p := range stack.Parameters {
					output.Add([]string{
						stack.AWSService,
						stack.Region,
						stack.Name,
						"Param",
						p.Key,
						p.Value,
						fmt.Sprintf("%f", p.Entropy),
						strings.Join(p.Hints, ",\n"),
					})
				}

				for _, r := range stack.Resources {
					output.Add([]string{
						stack.AWSService,
						stack.Region,
						stack.Name,
						r.Type,
						r.Name,
						"",
						"N/A",
						strings.Join(r.Hints, ",\n"),
					})
				}

				for _, o := range stack.Outputs {
					output.Add([]string{
						stack.AWSService,
						stack.Region,
						stack.Name,
						"Output",
						o.Key,
						o.Value,
						fmt.Sprintf("%f", o.Entropy),
						strings.Join(o.Hints, ",\n"),
					})
				}
			}

			if globalOpts.output != "" {
				return output.SaveAsCSV(globalOpts.output)
			}

			output.PrintTable()

			return nil
		},
	}

	cmd.Flags().Float64VarP(&opts.entropy, "entropy", "e", 0, "minimum entropy")
	cmd.Flags().BoolVarP(&opts.verify, "verify", "", false, "verify secrets")
	cmd.Flags().BoolVarP(&opts.ignoreCDKAssetParameters, "ignore-cdk-asset-parameter", "", false, "ignore cdk asset parameter")
	cmd.Flags().Float64VarP(&opts.highEntropyThreshold, "high-entropy-threshold", "", 3.5, "high entropy threshold")

	return cmd
}
