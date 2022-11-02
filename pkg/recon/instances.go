package recon

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/hupe1980/awsrecon/pkg/audit"
	"github.com/hupe1980/awsrecon/pkg/audit/secret"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type IMDS string

const (
	IMDSDisabled IMDS = "disabled"
	IMDSv1       IMDS = "v1"
	IMDSv2       IMDS = "v2"
)

type Instance struct {
	AWSService        string
	Region            string
	Name              string
	State             string
	VPCID             string
	AvailabilityZone  string
	PublicIP          string
	PrivateIP         string
	Architecture      string
	InstanceType      string
	NitroEnclaveState string
	UserDataState     string
	IMDS              IMDS
	InstanceProfile   string
	Hints             []string
}

type InstancesOptions struct {
	Verify               bool
	HighEntropyThreshold float64
}

type InstancesRecon struct {
	*recon[Instance]
	ec2Client *ec2.Client
	engine    *secret.Engine
	opts      InstancesOptions
}

func NewInstancesRecon(cfg *config.Config, optFns ...func(o *InstancesOptions)) *InstancesRecon {
	opts := InstancesOptions{
		Verify:               false,
		HighEntropyThreshold: 3.5,
	}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &InstancesRecon{
		ec2Client: ec2.NewFromConfig(cfg.AWSConfig),
		engine:    secret.NewEngine(opts.Verify),
		opts:      opts,
	}

	r.recon = newRecon[Instance](func() {
		r.runEnumeratePerRegion(cfg.Regions, func(region string) {
			r.enumerateInstancesPerRegion(region)
		})
	})

	return r
}

func (rec *InstancesRecon) enumerateInstancesPerRegion(region string) {
	p := ec2.NewDescribeInstancesPaginator(rec.ec2Client, &ec2.DescribeInstancesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *ec2.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.Reservations {
			for _, inst := range item.Instances {
				name := ""

				for _, tag := range inst.Tags {
					if aws.ToString(tag.Key) == "Name" {
						name = aws.ToString(tag.Value)
						break
					}
				}

				var hints []string

				userDataState := "Unknown"

				if userData, ok := rec.getUserData(inst.InstanceId, region); ok {
					if userData != "" {
						userDataState = fmt.Sprintf("%d", len(userData))

						hints = append(hints, rec.getHints(userData)...)
					} else {
						userDataState = "0"
					}
				}

				imds := IMDSDisabled
				if inst.MetadataOptions.HttpEndpoint == ec2Types.InstanceMetadataEndpointStateEnabled {
					imds = IMDSv1
					if inst.MetadataOptions.HttpTokens == ec2Types.HttpTokensStateRequired {
						imds = IMDSv2
					}
				}

				enclaveState := "Disabled"
				if aws.ToBool(inst.EnclaveOptions.Enabled) {
					enclaveState = "Enabled"
				}

				instanceProfile := "NoProfile"
				if inst.IamInstanceProfile != nil {
					instanceProfile = aws.ToString(inst.IamInstanceProfile.Arn)
					instanceProfile = strings.Split(instanceProfile, "/")[1]
				} else {
					hints = append(hints, "NoSSM")
				}

				if instanceProfile != "NoProfile" && imds == IMDSv1 {
					hints = append(hints, "SSRF")
				}

				publicIP := "NoPublicIP"
				if inst.PublicIpAddress != nil {
					publicIP = aws.ToString(inst.PublicIpAddress)
				}

				rec.addResult(Instance{
					AWSService:        "EC2",
					Region:            region,
					VPCID:             aws.ToString(inst.VpcId),
					AvailabilityZone:  aws.ToString(inst.Placement.AvailabilityZone),
					PublicIP:          publicIP,
					PrivateIP:         aws.ToString(inst.PrivateIpAddress),
					Name:              name,
					State:             string(inst.State.Name),
					NitroEnclaveState: enclaveState,
					UserDataState:     userDataState,
					IMDS:              imds,
					Architecture:      string(inst.Architecture),
					InstanceType:      string(inst.InstanceType),
					InstanceProfile:   instanceProfile,
					Hints:             hints,
				})
			}
		}
	}
}

func (rec *InstancesRecon) getUserData(id *string, region string) (string, bool) {
	attr, err := rec.ec2Client.DescribeInstanceAttribute(context.TODO(), &ec2.DescribeInstanceAttributeInput{
		InstanceId: id,
		Attribute:  ec2Types.InstanceAttributeNameUserData,
	}, func(o *ec2.Options) {
		o.Region = region
	})
	if err != nil {
		rec.addError(err)
		return "", false
	}

	if attr.UserData.Value == nil {
		return "", true
	}

	data, err := base64.StdEncoding.DecodeString(aws.ToString(attr.UserData.Value))
	if err != nil {
		rec.addError(err)
		return "", true
	}

	return string(data), true
}

func (rec *InstancesRecon) getHints(value string) []string {
	hints := rec.engine.Scan(value)

	entropy := audit.ShannonEntropy(value)

	if entropy > rec.opts.HighEntropyThreshold {
		hints = append(hints, "HighEntropy")
	}

	return hints
}
