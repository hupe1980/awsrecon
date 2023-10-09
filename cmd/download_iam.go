package cmd

import (
	"github.com/hupe1980/awsrecon/pkg/iam"
	"github.com/spf13/cobra"
)

type downloadIAMOptions struct {
	gzipFile bool
}

func newDownloadIAMCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &downloadIAMOptions{}
	cmd := &cobra.Command{
		Use:   "download-iam",
		Short: "Download iam definitions",

		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			def, err := iam.NewDefinitionFromReference()
			if err != nil {
				return err
			}

			return def.Save(globalOpts.output, opts.gzipFile)
		},
	}

	cmd.Flags().BoolVarP(&opts.gzipFile, "gzip", "", false, "gzip the file")

	return cmd
}
