package securitygroup

import (
	"context"
	"fmt"
	"net"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type Audit struct {
	ec2Client        ec2.DescribeSecurityGroupsAPIClient
	region           string
	groupIDs         []string
	myIP             *net.IP
	errors           []error
	openIngressPorts map[string]*OpenRange
	openEgressPorts  map[string]*OpenRange
}

func NewAudit(client *ec2.Client, region string, groupIDs []string, myIP *net.IP) *Audit {
	a := &Audit{
		ec2Client:        client,
		region:           region,
		groupIDs:         groupIDs,
		myIP:             myIP,
		openIngressPorts: make(map[string]*OpenRange),
		openEgressPorts:  make(map[string]*OpenRange),
	}

	if err := a.describeSecurityGroups(); err != nil {
		a.errors = append(a.errors, err)
	}

	return a
}

func (a *Audit) OpenIngressPorts() map[string]*OpenRange {
	return a.openIngressPorts
}

func (a *Audit) OpenEgressPorts() map[string]*OpenRange {
	return a.openEgressPorts
}

func (a *Audit) IsSSHOpenToAnywhere() bool {
	for _, entry := range []string{"all: all", "tcp: all", "tcp: 22"} {
		if _, ok := a.openIngressPorts[entry]; ok {
			return true
		}
	}

	return false
}

func (a *Audit) IsRDPOpenToAnywhere() bool {
	for _, entry := range []string{"all: all", "tcp: all", "tcp: 3389"} {
		if _, ok := a.openIngressPorts[entry]; ok {
			return true
		}
	}

	return false
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
			a.openIngressPorts["Unknown"] = &OpenRange{}
			a.openEgressPorts["Unknown"] = &OpenRange{}

			return err
		}

		for _, sg := range page.SecurityGroups {
			// Ingress
			for _, p := range sg.IpPermissions {
				for _, r := range p.IpRanges {
					// From Anywhere
					if r.CidrIp != nil && aws.ToString(r.CidrIp) == "0.0.0.0/0" {
						openRange := a.evaluateIPRange(p.IpProtocol, p.FromPort, p.ToPort)
						a.openIngressPorts[openRange.ToString()] = openRange
					}
				}

				for _, r := range p.Ipv6Ranges {
					// From Anywhere
					if r.CidrIpv6 != nil && aws.ToString(r.CidrIpv6) == "::/0" {
						openRange := a.evaluateIPRange(p.IpProtocol, p.FromPort, p.ToPort)
						a.openIngressPorts[openRange.ToString()] = openRange
					}
				}
			}

			// Egress
			for _, p := range sg.IpPermissionsEgress {
				for _, r := range p.IpRanges {
					// From Anywhere
					if r.CidrIp != nil && aws.ToString(r.CidrIp) == "0.0.0.0/0" {
						openRange := a.evaluateIPRange(p.IpProtocol, p.FromPort, p.ToPort)
						a.openEgressPorts[openRange.ToString()] = openRange
					}
				}

				for _, r := range p.Ipv6Ranges {
					// From Anywhere
					if r.CidrIpv6 != nil && aws.ToString(r.CidrIpv6) == "::/0" {
						openRange := a.evaluateIPRange(p.IpProtocol, p.FromPort, p.ToPort)
						a.openEgressPorts[openRange.ToString()] = openRange
					}
				}
			}
		}
	}

	return nil
}

func (a *Audit) evaluateIPRange(ipProtocol *string, fromPort *int32, toPort *int32) *OpenRange {
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
		return &OpenRange{
			Protocol: p,
			From:     f,
		}
	}

	return &OpenRange{
		Protocol: p,
		From:     f,
		To:       t,
	}
}
