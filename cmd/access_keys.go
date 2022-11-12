package cmd

import (
	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type accessKeysOptions struct {
	userNames []string
	ids       []string
}

func newAccessKeysCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &accessKeysOptions{}
	cmd := &cobra.Command{
		Use:           "access-keys",
		Short:         "Enumerate iam access-keys",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewAccessKeysRecon(cfg, func(o *recon.AccessKeysOptions) {
				o.UserNames = opts.userNames
				o.IDs = opts.ids
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			PrintInfof("Enumerating access-keys for account %s", cfg.Account)

			accessKeys := recon.Run()

			progress.Wait()

			output := output.New([]string{
				"Service",
				"UserName",
				"ID",
				"CreateDate",
				"Status",
			})

			for _, k := range accessKeys {
				output.Add([]string{
					k.AWSService,
					k.UserName,
					k.ID,
					k.CreateDate.String(),
					k.Status,
				})
			}

			output.PrintTable()

			if globalOpts.output != "" {
				if err := output.SaveAsCSV(globalOpts.output); err != nil {
					return err
				}

				PrintInfof("Output written to %s", globalOpts.output)
			}

			PrintInfof("%d access-keys enumerated.", len(accessKeys))

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&opts.userNames, "user", "u", nil, "user names")
	cmd.Flags().StringSliceVarP(&opts.ids, "key", "k", nil, "access-keys ids")

	return cmd
}
