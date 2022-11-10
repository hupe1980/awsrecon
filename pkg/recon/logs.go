package recon

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/hupe1980/awsrecon/pkg/audit/logmessage"
	"github.com/hupe1980/awsrecon/pkg/config"
)

var (
	DefaultGroupNamePrefix  = "/aws/lambda"
	DefaultStreamNamePrefix = fmt.Sprintf("%d", time.Now().Year())
)

type Log struct {
	AWSService string
	Region     string
	GroupName  string
	StreamName string
	Encrypted  bool
	Retention  string
	EventCount int
	Hints      []string
}

type LogsOptions struct {
	GroupNamePrefix  string
	StreamNamePrefix string
	FilterPattern    string
	StartTime        int64
	EndTime          int64
	Verify           bool
}

type LogsRecon struct {
	*recon[Log]
	cloudwatchlogsClient *cloudwatchlogs.Client
	engine               *logmessage.Engine
	opts                 LogsOptions
}

func NewLogsRecon(cfg *config.Config, optFns ...func(o *LogsOptions)) *LogsRecon {
	opts := LogsOptions{
		StartTime:        time.Now().Add(time.Hour * -24).UnixMilli(),
		EndTime:          math.MaxInt64,
		GroupNamePrefix:  DefaultGroupNamePrefix,
		StreamNamePrefix: DefaultStreamNamePrefix,
	}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &LogsRecon{
		cloudwatchlogsClient: cloudwatchlogs.NewFromConfig(cfg.AWSConfig),
		engine:               logmessage.NewEngine(opts.Verify),
		opts:                 opts,
	}

	r.recon = newRecon[Log](func() {
		r.runEnumerateServicePerRegion("cloudwatch", cfg.Regions, func(region string) {
			r.enumerateLogsPerRegion(region)
		})
	})

	return r
}

func (rec *LogsRecon) enumerateLogsPerRegion(region string) {
	p := cloudwatchlogs.NewDescribeLogGroupsPaginator(rec.cloudwatchlogsClient, &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String(rec.opts.GroupNamePrefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *cloudwatchlogs.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, g := range page.LogGroups {
			input := &cloudwatchlogs.FilterLogEventsInput{
				LogGroupName: g.LogGroupName,
				StartTime:    aws.Int64(rec.opts.StartTime),
				EndTime:      aws.Int64(rec.opts.EndTime),
			}

			if rec.opts.StreamNamePrefix != "" {
				input.LogStreamNamePrefix = aws.String(rec.opts.StreamNamePrefix)
			}

			if rec.opts.FilterPattern != "" {
				input.FilterPattern = aws.String(rec.opts.FilterPattern)
			}

			pe := cloudwatchlogs.NewFilterLogEventsPaginator(rec.cloudwatchlogsClient, input)
			for pe.HasMorePages() {
				eventPage, err := pe.NextPage(context.TODO(), func(o *cloudwatchlogs.Options) {
					o.Region = region
				})
				if err != nil {
					rec.addError(err)
					return
				}

				results := rec.engine.Scan(eventPage.Events)

				encrypted := false
				if g.KmsKeyId != nil {
					encrypted = true
				}

				retention := "Never expire"
				if g.RetentionInDays != nil {
					retention = fmt.Sprintf("%d", aws.ToInt32(g.RetentionInDays))
				}

				for k, v := range results {
					if v.Count == 0 {
						continue
					}

					rec.addResult(Log{
						AWSService: "Cloudwatch",
						Region:     region,
						GroupName:  aws.ToString(g.LogGroupName),
						Encrypted:  encrypted,
						Retention:  retention,
						StreamName: k,
						EventCount: v.Count,
						Hints:      v.Hints,
					})
				}
			}
		}
	}
}
