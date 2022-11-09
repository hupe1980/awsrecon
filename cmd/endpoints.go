package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hupe1980/awsrecon/pkg/common"
	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type endpointsOptions struct {
	ignoreServices []string
	onlyEndpoints  bool
}

func newEndpointsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &endpointsOptions{}
	cmd := &cobra.Command{
		Use:           "endpoints",
		Short:         "Enumerate endpoints",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			recon := recon.NewEndpointsRecon(cfg, func(o *recon.EndpointsOptions) {
				o.IgnoreServices = opts.ignoreServices
			})

			endpoints := recon.Run()

			if opts.onlyEndpoints {
				uniqueEndpoints := common.NewSet[string]()

				for _, e := range endpoints {
					uniqueEndpoints.Put(e.Endpoint)
				}

				uniqueEndpoints.Each(func(e string) {
					fmt.Println(e)
				})

				return nil
			}

			output := output.New([]string{
				"Service",
				"Region",
				"Name",
				"Type",
				"Endpoint",
				"Port",
				"Pro\ntocol",
				"Visi\nbility",
				"Hints",
			})

			sort.Slice(endpoints, func(i, j int) bool {
				return endpoints[i].AWSService < endpoints[j].AWSService
			})

			for _, e := range endpoints {
				output.Add([]string{
					e.AWSService,
					e.Region,
					e.Name,
					e.Type,
					e.Endpoint,
					fmt.Sprintf("%d", e.Port),
					e.Protocol,
					string(e.Visibility),
					strings.Join(e.Hints, ",\n"),
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
	cmd.PersistentFlags().BoolVarP(&opts.onlyEndpoints, "only-endpoints", "", false, "show only the endpoints")

	return cmd
}
