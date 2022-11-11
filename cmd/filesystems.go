package cmd

import (
	"sort"
	"strings"

	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type fileSystemsOptions struct {
	ignoreServices []string
}

func newFileSystemsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &fileSystemsOptions{}
	cmd := &cobra.Command{
		Use:           "filesystems",
		Short:         "Enumerate filesystems",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewFileSystemsRecon(cfg, func(o *recon.FileSystemsOptions) {
				o.IgnoreServices = opts.ignoreServices
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			fileSystems := recon.Run()

			progress.Wait()

			output := output.New([]string{
				"Service",
				"Region",
				"Name",
				"Hints",
			})

			sort.Slice(fileSystems, func(i, j int) bool {
				return fileSystems[i].AWSService < fileSystems[j].AWSService
			})

			for _, fs := range fileSystems {
				output.Add([]string{
					fs.AWSService,
					fs.Region,
					fs.Name,
					strings.Join(fs.Hints, ",\n"),
				})
			}

			if globalOpts.output != "" {
				return output.SaveAsCSV(globalOpts.output)
			}

			output.PrintTable()

			return nil
		},
	}

	cmd.PersistentFlags().StringSliceVarP(&opts.ignoreServices, "ignore-service", "", nil, "ignore services when enumeration")

	return cmd
}
