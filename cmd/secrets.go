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

type secretsOptions struct {
	entropy              float64
	decrypt              bool
	verify               bool
	highEntropyThreshold float64
	ignoreServices       []string
}

func newSecretsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &secretsOptions{}
	cmd := &cobra.Command{
		Use:           "secrets",
		Short:         "Enumerate secrets",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewSecretsRecon(cfg, func(o *recon.SecretsOptions) {
				o.Entropy = opts.entropy
				o.WithDecryption = opts.decrypt
				o.Verify = opts.verify
				o.HighEntropyThreshold = opts.highEntropyThreshold
				o.IgnoreServices = opts.ignoreServices
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			PrintInfof("Enumerating secrets for account %s", cfg.Account)

			secrets := recon.Run()

			progress.Wait()

			output := output.New([]string{
				"Service",
				"Region",
				"Type",
				"Name",
				"Value",
				"Entropy",
				"Hints",
			})

			sort.Slice(secrets, func(i, j int) bool {
				return secrets[i].AWSService < secrets[j].AWSService
			})

			for _, s := range secrets {
				output.Add([]string{
					s.AWSService,
					s.Region,
					s.Type,
					s.Name,
					s.Value,
					fmt.Sprintf("%f", s.Entropy),
					strings.Join(s.Hints, ",\n"),
				})
			}

			output.PrintTable()

			if globalOpts.output != "" {
				if err := output.SaveAsCSV(globalOpts.output); err != nil {
					return err
				}

				PrintInfof("Output written to %s", globalOpts.output)
			}

			PrintInfof("%d secrets enumerated.", len(secrets))

			return nil
		},
	}

	cmd.Flags().Float64VarP(&opts.entropy, "entropy", "e", 0, "minimum entropy")
	cmd.Flags().BoolVarP(&opts.decrypt, "decrypt", "d", false, "decrypt secret")
	cmd.Flags().BoolVarP(&opts.verify, "verify", "", false, "verify secrets")
	cmd.Flags().Float64VarP(&opts.highEntropyThreshold, "high-entropy-threshold", "", 3.5, "high entropy threshold")
	cmd.Flags().StringSliceVarP(&opts.ignoreServices, "ignore-service", "", nil, "ignore services when enumeration")

	return cmd
}
