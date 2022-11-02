package bucket

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/hupe1980/awsrecon/pkg/common"
	"github.com/hupe1980/awsrecon/pkg/iam"
)

const OAIPrefix = "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity"

var PublicACLUris = []string{"http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}

type PublicAccessBlockConfiguration struct {
	BlockPublicAcls       string
	BlockPublicPolicy     string
	IgnorePublicAcls      string
	RestrictPublicBuckets string
}

func (pabc *PublicAccessBlockConfiguration) BlocksNone() bool {
	if pabc.BlockPublicAcls == "Disabled" && pabc.BlockPublicPolicy == "Disabled" && pabc.IgnorePublicAcls == "Disabled" && pabc.RestrictPublicBuckets == "Disabled" {
		return true
	}

	return false
}

func (pabc *PublicAccessBlockConfiguration) BlocksAll() bool {
	if pabc.BlockPublicAcls == "Enabled" && pabc.BlockPublicPolicy == "Enabled" && pabc.IgnorePublicAcls == "Enabled" && pabc.RestrictPublicBuckets == "Enabled" {
		return true
	}

	return false
}

type Audit struct {
	s3Client                       *s3.Client
	name                           *string
	region                         string
	location                       string
	publicAccessBlockConfiguration *PublicAccessBlockConfiguration
	policyStatus                   string
	aclStatus                      string
	serverSideEncryptionStatus     string
	oaiCount                       int
	mfaDeleteStatus                string
	versioningStatus               string
	websiteConfigurationStatus     string
	errors                         []error
}

func NewAudit(client *s3.Client, name *string) *Audit {
	b := &Audit{
		s3Client: client,
		name:     name,
		location: "Unknown",
		publicAccessBlockConfiguration: &PublicAccessBlockConfiguration{
			BlockPublicAcls:       "Unknown",
			BlockPublicPolicy:     "Unknown",
			IgnorePublicAcls:      "Unknown",
			RestrictPublicBuckets: "Unknown",
		},
		policyStatus:               "Unknown",
		aclStatus:                  "Unknown",
		serverSideEncryptionStatus: "Unknown",
		oaiCount:                   -1,
		mfaDeleteStatus:            "Unknown",
		versioningStatus:           "Unknown",
		websiteConfigurationStatus: "Unknown",
	}

	if err := b.getBucketLocation(); err != nil {
		b.errors = append(b.errors, err)
	}

	if err := b.getPublicAccessBlock(); err != nil {
		b.errors = append(b.errors, err)
	}

	if err := b.getBucketPolicyStatus(); err != nil {
		b.errors = append(b.errors, err)
	}

	if err := b.getBucketACL(); err != nil {
		b.errors = append(b.errors, err)
	}

	if err := b.getBucketEncryption(); err != nil {
		b.errors = append(b.errors, err)
	}

	if err := b.getBucketVersioning(); err != nil {
		b.errors = append(b.errors, err)
	}

	if err := b.getBucketWebsite(); err != nil {
		b.errors = append(b.errors, err)
	}

	if err := b.getBucketPolicy(); err != nil {
		b.errors = append(b.errors, err)
	}

	return b
}

func (b *Audit) IsPublic() bool {
	if b.PolicyStatus() == "Public" || b.ACLStatus() == "Public" {
		if b.PublicAccessBlock().BlocksNone() {
			return true
		}
	}

	return false
}

func (b *Audit) Location() string {
	return b.location
}

func (b *Audit) PublicAccessBlock() *PublicAccessBlockConfiguration {
	return b.publicAccessBlockConfiguration
}

func (b *Audit) PolicyStatus() string {
	return b.policyStatus
}

func (b *Audit) ACLStatus() string {
	return b.aclStatus
}

func (b *Audit) ServerSideEncryptionStatus() string {
	return b.serverSideEncryptionStatus
}

func (b *Audit) OAICount() int {
	return b.oaiCount
}

func (b *Audit) MFADeleteStatus() string {
	return b.mfaDeleteStatus
}

func (b *Audit) VersioningStatus() string {
	return b.versioningStatus
}

func (b *Audit) WebsiteConfigurationStatus() string {
	return b.websiteConfigurationStatus
}

func (b *Audit) Errors() []error {
	return b.errors
}

func (b *Audit) getBucketLocation() error {
	output, err := b.s3Client.GetBucketLocation(context.TODO(), &s3.GetBucketLocationInput{
		Bucket: b.name,
	})
	if err != nil {
		b.region = "us-east-1" // try a default
		return err
	}

	b.location = string(output.LocationConstraint)

	if b.location == "" {
		// Buckets in Region us-east-1 have a LocationConstraint of null
		b.location = "us-east-1"
	}

	b.region = b.location

	return nil
}

func (b *Audit) getPublicAccessBlock() error {
	output, err := b.s3Client.GetPublicAccessBlock(context.TODO(), &s3.GetPublicAccessBlockInput{
		Bucket: b.name,
	}, func(o *s3.Options) {
		o.Region = b.region
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchPublicAccessBlockConfiguration" {
			b.publicAccessBlockConfiguration.BlockPublicAcls = "Disabled"
			b.publicAccessBlockConfiguration.BlockPublicPolicy = "Disabled"
			b.publicAccessBlockConfiguration.IgnorePublicAcls = "Disabled"
			b.publicAccessBlockConfiguration.RestrictPublicBuckets = "Disabled"

			return nil
		}

		return err
	}

	b.publicAccessBlockConfiguration.BlockPublicAcls = "Disabled"
	if output.PublicAccessBlockConfiguration.BlockPublicAcls {
		b.publicAccessBlockConfiguration.BlockPublicAcls = "Enabled"
	}

	b.publicAccessBlockConfiguration.BlockPublicPolicy = "Disabled"
	if output.PublicAccessBlockConfiguration.BlockPublicPolicy {
		b.publicAccessBlockConfiguration.BlockPublicPolicy = "Enabled"
	}

	b.publicAccessBlockConfiguration.IgnorePublicAcls = "Disabled"
	if output.PublicAccessBlockConfiguration.IgnorePublicAcls {
		b.publicAccessBlockConfiguration.IgnorePublicAcls = "Enabled"
	}

	b.publicAccessBlockConfiguration.RestrictPublicBuckets = "Disabled"
	if output.PublicAccessBlockConfiguration.RestrictPublicBuckets {
		b.publicAccessBlockConfiguration.RestrictPublicBuckets = "Enabled"
	}

	return nil
}

func (b *Audit) getBucketPolicyStatus() error {
	output, err := b.s3Client.GetBucketPolicyStatus(context.TODO(), &s3.GetBucketPolicyStatusInput{
		Bucket: b.name,
	}, func(o *s3.Options) {
		o.Region = b.region
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchBucketPolicy" {
			b.policyStatus = "Private"
			return nil
		}

		return err
	}

	b.policyStatus = "Private"
	if output.PolicyStatus.IsPublic {
		b.policyStatus = "Public"
	}

	return nil
}

func (b *Audit) getBucketACL() error {
	output, err := b.s3Client.GetBucketAcl(context.TODO(), &s3.GetBucketAclInput{
		Bucket: b.name,
	}, func(o *s3.Options) {
		o.Region = b.region
	})
	if err != nil {
		return err
	}

	b.aclStatus = "Private"

	for _, g := range output.Grants {
		if g.Grantee.Type != s3Types.TypeGroup || g.Grantee.URI == nil {
			continue
		}

		if common.SliceContains(PublicACLUris, aws.ToString(g.Grantee.URI)) {
			b.aclStatus = "Public"
		}
	}

	return nil
}

func (b *Audit) getBucketEncryption() error {
	output, err := b.s3Client.GetBucketEncryption(context.TODO(), &s3.GetBucketEncryptionInput{
		Bucket: b.name,
	}, func(o *s3.Options) {
		o.Region = b.region
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError" {
			b.serverSideEncryptionStatus = "Disabled"
			return nil
		}

		return err
	}

	b.serverSideEncryptionStatus = "Disabled"

	if len(output.ServerSideEncryptionConfiguration.Rules) == 1 {
		switch output.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm {
		case s3Types.ServerSideEncryptionAes256:
			b.serverSideEncryptionStatus = "AES256"
		case s3Types.ServerSideEncryptionAwsKms:
			b.serverSideEncryptionStatus = "KMS"
		default:
			b.serverSideEncryptionStatus = "Unknown-Algorithm"
		}
	}

	return nil
}

func (b *Audit) getBucketPolicy() error {
	output, err := b.s3Client.GetBucketPolicy(context.TODO(), &s3.GetBucketPolicyInput{
		Bucket: b.name,
	}, func(o *s3.Options) {
		o.Region = b.region
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchBucketPolicy" {
			b.oaiCount = 0
			return nil
		}

		return err
	}

	doc, err := iam.ConvertToPolicyDocument(aws.ToString(output.Policy))
	if err != nil {
		return err
	}

	b.oaiCount = 0

	for _, s := range doc.Statements {
		if principals, ok := s.Principal["AWS"]; ok {
			for _, p := range principals {
				if strings.HasPrefix(string(p), OAIPrefix) {
					b.oaiCount = b.oaiCount + 1
				}
			}
		}
	}

	return nil
}

func (b *Audit) getBucketVersioning() error {
	output, err := b.s3Client.GetBucketVersioning(context.TODO(), &s3.GetBucketVersioningInput{
		Bucket: b.name,
	}, func(o *s3.Options) {
		o.Region = b.region
	})
	if err != nil {
		return err
	}

	b.mfaDeleteStatus = "Disabled"
	if output.MFADelete == s3Types.MFADeleteStatusEnabled {
		b.mfaDeleteStatus = "Enabled"
	}

	b.versioningStatus = "Disabled"
	if output.Status == s3Types.BucketVersioningStatusEnabled || output.Status == s3Types.BucketVersioningStatusSuspended {
		b.versioningStatus = string(output.Status)
	}

	return nil
}

func (b *Audit) getBucketWebsite() error {
	output, err := b.s3Client.GetBucketWebsite(context.TODO(), &s3.GetBucketWebsiteInput{
		Bucket: b.name,
	}, func(o *s3.Options) {
		o.Region = b.region
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchWebsiteConfiguration" {
			b.websiteConfigurationStatus = "NoCFG"
			return nil
		}

		return err
	}

	if output.RedirectAllRequestsTo != nil {
		b.websiteConfigurationStatus = "Redirect"
	} else {
		b.websiteConfigurationStatus = "Website"
	}

	return nil
}
