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

// type endpointsOptions struct {
// }

func newEndpointsCmd(globalOpts *globalOptions) *cobra.Command {
	// opts := &endpointsOptions{}
	cmd := &cobra.Command{
		Use:           "endpoints",
		Short:         "Enumerate endpoints",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent, globalOpts.timeout)
			if err != nil {
				return err
			}

			recon := recon.NewEndpointsRecon(cfg)

			endpoints := recon.Run()

			output := output.NewTable([]string{
				"Service",
				"Region",
				"Name",
				"Endpoint",
				"Port",
				"Pro-\ntocol",
				"Visi-\nbility",
				"Hints",
			})

			sort.Slice(endpoints, func(i, j int) bool {
				return endpoints[i].AWSService < endpoints[j].AWSService
			})

			for _, e := range endpoints {
				output.Add([]string{e.AWSService, e.Region, e.Name, e.Endpoint, fmt.Sprintf("%d", e.Port), e.Protocol, string(e.Visibility), strings.Join(e.Hints, ",\n")})
			}

			output.Print()

			return nil
		},
	}

	return cmd
}
