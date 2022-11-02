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

type tagsOptions struct {
	entropy              float64
	verify               bool
	highEntropyThreshold float64
}

func newTagsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &tagsOptions{}
	cmd := &cobra.Command{
		Use:           "tags",
		Short:         "Enumerate tags",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent, globalOpts.timeout)
			if err != nil {
				return err
			}

			recon := recon.NewTagsRecon(cfg, func(o *recon.TagsOptions) {
				o.Entropy = opts.entropy
				o.Verify = opts.verify
				o.HighEntropyThreshold = opts.highEntropyThreshold
			})

			tags := recon.Run()

			output := output.NewTable([]string{"Service", "Region", "Name", "Key", "Value", "Entropy", "Hints"})

			sort.Slice(tags, func(i, j int) bool {
				return tags[i].AWSService < tags[j].AWSService
			})

			for _, t := range tags {
				output.Add([]string{t.AWSService, t.Region, t.Name, t.Key, t.Value, fmt.Sprintf("%f", t.Entropy), strings.Join(t.Hints, ", ")})
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
