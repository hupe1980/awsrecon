package cmd

import (
	"strings"

	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type functionsOptions struct {
	names []string
}

func newFunctionsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &functionsOptions{}
	cmd := &cobra.Command{
		Use:           "functions",
		Short:         "Enumerate lambda functions",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewFunctionsRecon(cfg, func(o *recon.FunctionsOptions) {
				o.Names = opts.names
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			functions := recon.Run()

			progress.Wait()

			output := output.New([]string{
				"Service",
				"Region",
				"Name",
				"Runtime",
				"Hints",
			})

			for _, f := range functions {
				output.Add([]string{
					f.AWSService,
					f.Region,
					f.Name,
					f.Runtime,
					strings.Join(f.Hints, ",\n"),
				})
			}

			if globalOpts.output != "" {
				return output.SaveAsCSV(globalOpts.output)
			}

			output.PrintTable()

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&opts.names, "name", "n", nil, "function name")

	return cmd
}
