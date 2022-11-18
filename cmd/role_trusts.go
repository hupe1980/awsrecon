package cmd

import (
	"strings"

	"github.com/hupe1980/awsrecon/pkg/config"
	"github.com/hupe1980/awsrecon/pkg/output"
	"github.com/hupe1980/awsrecon/pkg/recon"
	"github.com/spf13/cobra"
)

type roleTrustsOptions struct {
	ignoreServiceLinkRoles bool
}

func newRoleTrustsCmd(globalOpts *globalOptions) *cobra.Command {
	opts := &roleTrustsOptions{}
	cmd := &cobra.Command{
		Use:           "role-trusts",
		Short:         "Enumerate iam role-trusts",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.NewConfig(globalOpts.profile, globalOpts.regions, globalOpts.userAgent)
			if err != nil {
				return err
			}

			progress := output.NewProgress()

			recon := recon.NewRoleTrustsRecon(cfg, func(o *recon.RoleTrustsOptions) {
				o.IgnoreServiceLinkRoles = opts.ignoreServiceLinkRoles
				o.BeforeHook = progress.BeforeHook()
				o.AfterRunHook = progress.AfterRunHook()
			})

			PrintInfof("Enumerating role-trusts for account %s", cfg.Account)

			roleTrusts := recon.Run()

			progress.Wait()

			output := output.New([]string{
				"Service",
				"RoleName",
				"CreateDate",
				//"LastUsedDate",
				//"LastUsedRegion",
				"Principal",
				"TrustedEntity",
				"ExternalID",
				"Hints",
			})

			for _, r := range roleTrusts {
				// lastUsedDate := ""
				// if !r.LastUsedDate.IsZero() {
				// 	lastUsedDate = r.LastUsedDate.String()
				// }

				output.Add([]string{
					r.AWSService,
					r.RoleName,
					r.CreateDate.String(),
					//lastUsedDate,
					//r.LastUsedRegion,
					r.Principal,
					r.TrustedEntity,
					r.ExternalID,
					strings.Join(r.Hints, ",\n"),
				})
			}

			output.PrintTable()

			if globalOpts.output != "" {
				if err := output.SaveAsCSV(globalOpts.output); err != nil {
					return err
				}

				PrintInfof("Output written to %s", globalOpts.output)
			}

			PrintInfof("%d role-trusts enumerated.", len(roleTrusts))

			return nil
		},
	}

	cmd.Flags().BoolVarP(&opts.ignoreServiceLinkRoles, "ignore-service-link-roles", "", false, "ignore service link roles")

	return cmd
}
