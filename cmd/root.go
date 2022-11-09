package cmd

import (
	"fmt"
	"os"

	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/spf13/cobra"
)

func Execute(version string) {
	rootCmd := newRootCmd(version)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

type globalOptions struct {
	profile   string
	regions   []string
	userAgent string
	output    string
}

func newRootCmd(version string) *cobra.Command {
	globalOpts := &globalOptions{}

	cmd := &cobra.Command{
		Use:           "awsrecon",
		Version:       version,
		Short:         "AWSrecon is a tool for reconnaissance AWS cloud environments",
		SilenceErrors: true,
	}

	cmd.PersistentFlags().StringVarP(&globalOpts.profile, "profile", "", "", "AWS profile")
	cmd.PersistentFlags().StringSliceVarP(&globalOpts.regions, "region", "", nil, "AWS regions (default all aws regions)")
	cmd.PersistentFlags().StringVarP(&globalOpts.userAgent, "user-agent", "A", config.DefaultUserAgent, "user-agent to use")
	cmd.PersistentFlags().StringVarP(&globalOpts.output, "output", "o", "", "output filename")

	cmd.AddCommand(
		newBucketsCmd(globalOpts),
		newEndpointsCmd(globalOpts),
		newEnvsCmd(globalOpts),
		newFileSystemsCmd(globalOpts),
		newFunctionsCmd(globalOpts),
		newInstancesCmd(globalOpts),
		newLogsCmd(globalOpts),
		newPrincipalsCmd(globalOpts),
		newRecordsCmd(globalOpts),
		newReposCmd(globalOpts),
		newSecretsCmd(globalOpts),
		newStacksCmd(globalOpts),
		newTagsCmd(globalOpts),
		newDownloadIAMCmd(globalOpts),
	)

	return cmd
}
