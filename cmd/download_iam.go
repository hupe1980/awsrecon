package cmd

import (
	"github.com/hupe1980/awsrecon/pkg/iam"
	"github.com/spf13/cobra"
)

type downloadIAMOptions struct {
	outdir string
}

func newDownloadIAMCmd() *cobra.Command {
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

			if err = def.Save(opts.outdir); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.outdir, "outdir", "o", ".", "output directory")

	return cmd
}
