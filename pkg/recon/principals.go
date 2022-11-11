package recon

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/hupe1980/awsrecon/pkg/audit/permission"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type PrincipalsOptions struct {
	IgnoreServices []string
	BeforeHook     BeforeHookFunc
	AfterRunHook   AfterRunHookFunc
}

type Principal struct {
	AWSService       string
	Type             string
	ARN              string
	Name             string
	AttachedPolicies []iamTypes.AttachedPolicy
	InlinePolicies   []iamTypes.PolicyDetail
	Findings         []string
}

type PrincipalsRecon struct {
	*recon[Principal]
	iamClient *iam.Client
	engine    *permission.Engine
}

func NewPrincipalsRecon(cfg *config.Config, optFns ...func(o *PrincipalsOptions)) (*PrincipalsRecon, error) {
	opts := PrincipalsOptions{}

	for _, fn := range optFns {
		fn(&opts)
	}

	e, err := permission.NewEngine()
	if err != nil {
		return nil, err
	}

	r := &PrincipalsRecon{
		iamClient: iam.NewFromConfig(cfg.AWSConfig),
		engine:    e,
	}

	r.recon = newRecon[Principal](func() {
		r.runEnumerateService("user", func() {
			r.enumerateUsers()
		})

		r.runEnumerateService("group", func() {
			r.enumerateGroups()
		})

		r.runEnumerateService("role", func() {
			r.enumerateRoles()
		})
	}, func(o *reconOptions) {
		o.IgnoreServices = opts.IgnoreServices
		o.BeforeHook = opts.BeforeHook
		o.AfterRunHook = opts.AfterRunHook
	})

	return r, nil
}

func (rec *PrincipalsRecon) enumerateUsers() {
	p := iam.NewGetAccountAuthorizationDetailsPaginator(rec.iamClient, &iam.GetAccountAuthorizationDetailsInput{
		Filter: []iamTypes.EntityType{iamTypes.EntityTypeUser},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO())
		if err != nil {
			rec.addError(err)
			return
		}

		for _, detail := range page.UserDetailList {
			rec.addResult(Principal{
				AWSService:       "IAM",
				Type:             "User",
				ARN:              aws.ToString(detail.Arn),
				Name:             aws.ToString(detail.UserName),
				InlinePolicies:   detail.UserPolicyList,
				AttachedPolicies: detail.AttachedManagedPolicies,
			})
		}
	}
}

func (rec *PrincipalsRecon) enumerateGroups() {
	p := iam.NewGetAccountAuthorizationDetailsPaginator(rec.iamClient, &iam.GetAccountAuthorizationDetailsInput{
		Filter: []iamTypes.EntityType{iamTypes.EntityTypeGroup},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO())
		if err != nil {
			rec.addError(err)
			return
		}

		for _, detail := range page.GroupDetailList {
			rec.addResult(Principal{
				AWSService:       "IAM",
				Type:             "Group",
				ARN:              aws.ToString(detail.Arn),
				Name:             aws.ToString(detail.GroupName),
				InlinePolicies:   detail.GroupPolicyList,
				AttachedPolicies: detail.AttachedManagedPolicies,
			})
		}
	}
}

func (rec *PrincipalsRecon) enumerateRoles() {
	p := iam.NewGetAccountAuthorizationDetailsPaginator(rec.iamClient, &iam.GetAccountAuthorizationDetailsInput{
		Filter: []iamTypes.EntityType{iamTypes.EntityTypeRole},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO())
		if err != nil {
			rec.addError(err)
			return
		}

		for _, detail := range page.RoleDetailList {
			rec.addResult(Principal{
				AWSService:       "IAM",
				Type:             "Role",
				ARN:              aws.ToString(detail.Arn),
				Name:             aws.ToString(detail.RoleName),
				InlinePolicies:   detail.RolePolicyList,
				AttachedPolicies: detail.AttachedManagedPolicies,
			})
		}
	}
}
