package cmd

import (
	"fmt"
	"strings"

	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type recordsOptions struct {
	verify bool
}

func newRecordsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &recordsOptions{}
	cmd := &cobra.Command{
		Use:           "records",
		Short:         "Enumerate dns records",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewRecordsRecon(cfg, func(o *recon.RecordsOptions) {
				o.Verify = opts.verify
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			PrintInfof("Enumerating records for account %s", cfg.Account)

			records := recon.Run()

			progress.Wait()

			output := output.New([]string{
				"Service",
				"Zone",
				"Name",
				"Type",
				"Value",
				"PrivateZone",
				"Hints",
			})

			for _, record := range records {
				output.Add([]string{
					record.AWSService,
					record.Zone,
					record.Name,
					record.Type,
					record.Value,
					fmt.Sprintf("%t", record.PrivateZone),
					strings.Join(record.Hints, ",\n"),
				})
			}

			output.PrintTable()

			if globalOpts.output != "" {
				if err := output.SaveAsCSV(globalOpts.output); err != nil {
					return err
				}

				PrintInfof("Output written to %s", globalOpts.output)
			}

			PrintInfof("%d records enumerated.", len(records))

			return nil
		},
	}

	cmd.Flags().BoolVarP(&opts.verify, "verify", "", false, "verify takeover vulnerability")

	return cmd
}
