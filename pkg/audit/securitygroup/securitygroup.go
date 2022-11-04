package securitygroup

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/hupe1980/awsrecon/pkg/common"
)

type Audit struct {
	ec2Client                    *ec2.Client
	region                       string
	groupIDs                     []string
	errors                       []error
	openFromAnywhereIngressPorts common.Set[string]
	openToAnywhereEgressPorts    common.Set[string]
}

func NewAudit(client *ec2.Client, region string, groupIDs []string) *Audit {
	a := &Audit{
		ec2Client:                    client,
		region:                       region,
		groupIDs:                     groupIDs,
		openFromAnywhereIngressPorts: common.NewSet[string](),
		openToAnywhereEgressPorts:    common.NewSet[string](),
	}

	if err := a.describeSecurityGroups(); err != nil {
		a.errors = append(a.errors, err)
	}

	return a
}

func (a *Audit) OpenFromAnywhereIngressPorts() []string {
	return a.openFromAnywhereIngressPorts.ToSlice()
}

func (a *Audit) OpenToAnywhereEgressPorts() []string {
	return a.openToAnywhereEgressPorts.ToSlice()
}

func (a *Audit) IsSSHOpenToAnywhere() bool {
	return common.SliceContains(a.OpenFromAnywhereIngressPorts(), "tcp: 22")
}

func (a *Audit) IsRDPOpenToAnywhere() bool {
	return common.SliceContains(a.OpenFromAnywhereIngressPorts(), "tcp: 3389")
}

func (a *Audit) describeSecurityGroups() error {
	p := ec2.NewDescribeSecurityGroupsPaginator(a.ec2Client, &ec2.DescribeSecurityGroupsInput{
		GroupIds: a.groupIDs,
	})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *ec2.Options) {
			o.Region = a.region
		})
		if err != nil {
			a.openFromAnywhereIngressPorts.Put("Unknown")
			a.openToAnywhereEgressPorts.Put("Unknown")

			return err
		}

		for _, sg := range page.SecurityGroups {
			// Ingress
			for _, p := range sg.IpPermissions {
				for _, r := range p.IpRanges {
					// From Anywhere
					if r.CidrIp != nil && aws.ToString(r.CidrIp) == "0.0.0.0/0" {
						a.openFromAnywhereIngressPorts.Put(a.evaluateIPRange(p.IpProtocol, p.FromPort, p.ToPort))
					}
				}

				for _, r := range p.Ipv6Ranges {
					// From Anywhere
					if r.CidrIpv6 != nil && aws.ToString(r.CidrIpv6) == "::/0" {
						a.openFromAnywhereIngressPorts.Put(a.evaluateIPRange(p.IpProtocol, p.FromPort, p.ToPort))
					}
				}
			}

			// Egress
			for _, p := range sg.IpPermissionsEgress {
				for _, r := range p.IpRanges {
					// From Anywhere
					if r.CidrIp != nil && aws.ToString(r.CidrIp) == "0.0.0.0/0" {
						a.openToAnywhereEgressPorts.Put(a.evaluateIPRange(p.IpProtocol, p.FromPort, p.ToPort))
					}
				}

				for _, r := range p.Ipv6Ranges {
					// From Anywhere
					if r.CidrIpv6 != nil && aws.ToString(r.CidrIpv6) == "::/0" {
						a.openToAnywhereEgressPorts.Put(a.evaluateIPRange(p.IpProtocol, p.FromPort, p.ToPort))
					}
				}
			}
		}
	}

	return nil
}

func (a *Audit) evaluateIPRange(ipProtocol *string, fromPort *int32, toPort *int32) string {
	f := fmt.Sprintf("%d", aws.ToInt32(fromPort))
	t := fmt.Sprintf("%d", aws.ToInt32(toPort))
	p := aws.ToString(ipProtocol)

	if f == "-1" {
		f = "all"
	}

	if t == "-1" {
		t = "all"
	}

	if p == "-1" {
		p = "all"
		f = "all"
		t = "all"
	}

	if f == t {
		return fmt.Sprintf("%s: %s", p, f)
	}

	return fmt.Sprintf("%s: %s-%s", p, f, t)
}
