package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type envsOptions struct {
	entropy              float64
	verify               bool
	highEntropyThreshold float64
}

func newEnvsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &envsOptions{}
	cmd := &cobra.Command{
		Use:           "envs",
		Short:         "Enumerate environment variables",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent, globalOpts.timeout)
			if err != nil {
				return err
			}

			recon := recon.NewEnvsRecon(cfg, func(o *recon.EnvsOptions) {
				o.Entropy = opts.entropy
				o.Verify = opts.verify
				o.HighEntropyThreshold = opts.highEntropyThreshold
			})

			envs := recon.Run()

			output := output.NewTable([]string{
				"Service",
				"Region",
				"Name",
				"Key",
				"Value",
				"Entropy",
				"Findings",
			})

			sort.Slice(envs, func(i, j int) bool {
				return envs[i].AWSService < envs[j].AWSService
			})

			for _, env := range envs {
				output.Add([]string{
					env.AWSService,
					env.Region,
					env.Name,
					env.Key,
					env.Value,
					fmt.Sprintf("%f", env.Entropy),
					strings.Join(env.Hints, ", "),
				})
			}

			output.Print()

			return nil
		},
	}

	cmd.Flags().Float64VarP(&opts.entropy, "entropy", "e", 0, "minimum entropy")
	cmd.Flags().BoolVarP(&opts.verify, "verify", "", false, "verify secrets")
	cmd.Flags().Float64VarP(&opts.highEntropyThreshold, "high-entropy-threshold", "", 3.5, "high entropy threshold")

	return cmd
}