package cmd

import (
	"fmt"
	"strings"

	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type logsOptions struct {
	verify           bool
	groupNamePrefix  string
	streamNamePrefix string
	filterPattern    string
	startTime        int64
	endTime          int64
}

func newLogsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &logsOptions{}
	cmd := &cobra.Command{
		Use:           "logs",
		Short:         "Enumerate cloudwatch logs",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewLogsRecon(cfg, func(o *recon.LogsOptions) {
				o.Verify = opts.verify
				o.GroupNamePrefix = opts.groupNamePrefix
				o.StreamNamePrefix = opts.streamNamePrefix
				o.FilterPattern = opts.filterPattern
				o.StartTime = opts.startTime
				o.EndTime = opts.endTime
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			PrintInfof("Enumerating logs for account %s", cfg.Account)

			logs := recon.Run()

			progress.Wait()

			output := output.New([]string{
				"Service",
				"Region",
				"GroupName",
				"StreamName",
				"Events",
				"Encrypted",
				"Retention",
				"Hints",
			})

			for _, l := range logs {
				output.Add([]string{
					l.AWSService,
					l.Region,
					l.GroupName,
					l.StreamName,
					fmt.Sprintf("%d", l.EventCount),
					fmt.Sprintf("%v", l.Encrypted),
					l.Retention,
					strings.Join(l.Hints, ",\n"),
				})
			}

			output.PrintTable()

			if globalOpts.output != "" {
				if err := output.SaveAsCSV(globalOpts.output); err != nil {
					return err
				}

				PrintInfof("Output written to %s", globalOpts.output)
			}

			PrintInfof("%d logs enumerated.", len(logs))

			return nil
		},
	}

	cmd.Flags().BoolVarP(&opts.verify, "verify", "", false, "verify secrets")
	cmd.Flags().StringVarP(&opts.groupNamePrefix, "group-name-prefix", "", recon.DefaultGroupNamePrefix, "group name prefix to match")
	cmd.Flags().StringVarP(&opts.streamNamePrefix, "stream-name-prefix", "", recon.DefaultStreamNamePrefix, "stream name prefix to match")
	cmd.Flags().StringVarP(&opts.filterPattern, "filter-pattern", "", "", "filter pattern to match")
	cmd.Flags().Int64VarP(&opts.startTime, "start-time", "", 0, "start of the time range (default last 24h)")
	cmd.Flags().Int64VarP(&opts.startTime, "end-time", "", 0, "end of the time range (default open end)")

	return cmd
}
