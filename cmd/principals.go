package cmd

import (
	"sort"

	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

// type principalsOptions struct {
// }

func newPrincipalsCmd(globalOpts *globalOptions) *cobra.Command {
	// opts := &principalsOptions{}
	cmd := &cobra.Command{
		Use:           "principals",
		Short:         "Enumerate iam principals",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon, err := recon.NewPrincipalsRecon(cfg, func(o *recon.PrincipalsOptions) {
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})
			if err != nil {
				return err
			}

			PrintInfof("Enumerating principals for account %s", cfg.Account)

			principals := recon.Run()

			progress.Wait()

			output := output.New([]string{
				"Service",
				"Type",
				"Name",
			})

			sort.Slice(principals, func(i, j int) bool {
				return principals[i].AWSService < principals[j].AWSService
			})

			for _, p := range principals {
				output.Add([]string{
					p.AWSService,
					p.Type,
					p.Name,
				})
			}

			output.PrintTable()

			if globalOpts.output != "" {
				if err := output.SaveAsCSV(globalOpts.output); err != nil {
					return err
				}

				PrintInfof("Output written to %s", globalOpts.output)
			}

			PrintInfof("%d principals enumerated.", len(principals))

			return nil
		},
	}

	return cmd
}
