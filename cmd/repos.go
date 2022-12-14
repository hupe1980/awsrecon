package cmd

import (
	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type reposOptions struct {
	entropy              float64
	verify               bool
	highEntropyThreshold float64
}

func newReposCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &reposOptions{}
	cmd := &cobra.Command{
		Use:           "repos",
		Short:         "Enumerate codecommit repositories",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewReposRecon(cfg, func(o *recon.ReposOptions) {
				o.Entropy = opts.entropy
				o.Verify = opts.verify
				o.HighEntropyThreshold = opts.highEntropyThreshold
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			PrintInfof("Enumerating repos for account %s", cfg.Account)

			repos := recon.Run()

			progress.Wait()

			output := output.New([]string{
				"Service",
				"Region",
				"Name",
				"CloneURL",
			})

			for _, r := range repos {
				output.Add([]string{
					r.AWSService,
					r.Region,
					r.Name,
					r.CloneURLHTTP,
				})
			}

			output.PrintTable()

			if globalOpts.output != "" {
				if err := output.SaveAsCSV(globalOpts.output); err != nil {
					return err
				}

				PrintInfof("Output written to %s", globalOpts.output)
			}

			PrintInfof("%d repos enumerated.", len(repos))

			return nil
		},
	}

	cmd.Flags().Float64VarP(&opts.entropy, "entropy", "e", 0, "minimum entropy")
	cmd.Flags().BoolVarP(&opts.verify, "verify", "", false, "verify secrets")
	cmd.Flags().Float64VarP(&opts.highEntropyThreshold, "high-entropy-threshold", "", 3.5, "high entropy threshold")

	return cmd
}
