package recon

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53Types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/hupe1980/awsrecon/pkg/audit/takeover"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type Record struct {
	AWSService  string
	Zone        string
	Name        string
	Type        string
	Value       string
	PrivateZone bool
	Hints       []string
}

type RecordsOptions struct {
	Verify       bool
	BeforeHook   BeforeHookFunc
	AfterRunHook AfterRunHookFunc
}

type RecordsRecon struct {
	*recon[Record]
	route53Client *route53.Client
	engine        *takeover.Engine
	opts          RecordsOptions
}

func NewRecordsRecon(cfg *config.Config, optFns ...func(o *RecordsOptions)) *RecordsRecon {
	opts := RecordsOptions{
		Verify: false,
	}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &RecordsRecon{
		route53Client: route53.NewFromConfig(cfg.AWSConfig),
		engine:        takeover.New(opts.Verify),
		opts:          opts,
	}

	r.recon = newRecon[Record](func() {
		r.runEnumerateService("route53", func() {
			r.enumerateRecords()
		})
	}, func(o *reconOptions) {
		o.BeforeHook = opts.BeforeHook
		o.AfterRunHook = opts.AfterRunHook
	})

	return r
}

func (rec *RecordsRecon) enumerateRecords() {
	p := route53.NewListHostedZonesPaginator(rec.route53Client, &route53.ListHostedZonesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO())
		if err != nil {
			rec.addError(err)
			return
		}

		for _, zone := range page.HostedZones {
			output, err := rec.route53Client.ListResourceRecordSets(
				context.TODO(),
				&route53.ListResourceRecordSetsInput{
					HostedZoneId: zone.Id,
					MaxItems:     aws.Int32(100),
				},
			)
			if err != nil {
				rec.addError(err)
				continue
			}

			privateZone := false
			if zone.Config.PrivateZone {
				privateZone = true
			}

			for _, recordSet := range output.ResourceRecordSets {
				if recordSet.AliasTarget != nil {
					rec.addResult(Record{
						AWSService:  "Route53",
						Zone:        aws.ToString(zone.Name),
						Name:        aws.ToString(recordSet.Name),
						Type:        string(recordSet.Type),
						Value:       fmt.Sprintf("ALIAS %s", aws.ToString(recordSet.AliasTarget.DNSName)),
						PrivateZone: privateZone,
					})
				}

				for _, record := range recordSet.ResourceRecords {
					name := aws.ToString(recordSet.Name)

					var hints []string

					if recordSet.Type == route53Types.RRTypeCname {
						if result := rec.engine.CheckCName(name); result != nil {
							if result.Verified {
								hints = append(hints, "TakeoverVulnerability")
							} else {
								hints = append(hints, "TakeoverPossibility")
							}
						}
					}

					rec.addResult(Record{
						AWSService:  "Route53",
						Zone:        aws.ToString(zone.Name),
						Name:        name,
						Type:        string(recordSet.Type),
						Value:       aws.ToString(record.Value),
						PrivateZone: privateZone,
						Hints:       hints,
					})
				}
			}
		}
	}
}
