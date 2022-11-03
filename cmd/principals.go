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
		Short:         "Enumerate principals",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent, globalOpts.timeout)
			if err != nil {
				return err
			}

			recon, err := recon.NewPrincipalsRecon(cfg)
			if err != nil {
				return err
			}

			principals := recon.Run()

			output := output.New([]string{"Service", "Type", "Name"})

			sort.Slice(principals, func(i, j int) bool {
				return principals[i].AWSService < principals[j].AWSService
			})

			for _, p := range principals {
				output.Add([]string{p.AWSService, p.Type, p.Name})
			}

			if globalOpts.output != "" {
				return output.SaveAsCSV(globalOpts.output)
			}

			output.PrintTable()

			return nil
		},
	}

	return cmd
}
