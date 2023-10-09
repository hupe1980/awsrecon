package recon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/hupe1980/awsrecon/pkg/common"
	"github.com/hupe1980/awsrecon/pkg/config"
	reconIam "github.com/hupe1980/awsrecon/pkg/iam"
)

type RoleTrust struct {
	AWSService     string
	RoleName       string
	RoleARN        string
	CreateDate     time.Time
	LastUsedDate   time.Time
	LastUsedRegion string
	Principal      string
	TrustedEntity  string
	ExternalID     string
	Hints          []string
}

type RoleTrustsOptions struct {
	IgnoreServiceLinkRoles bool
	BeforeHook             BeforeHookFunc
	AfterRunHook           AfterRunHookFunc
}

type RoleTrustsRecon struct {
	*recon[RoleTrust]
	iamClient iam.ListRolesAPIClient
	opts      RoleTrustsOptions
	account   string
}

func NewRoleTrustsRecon(cfg *config.Config, optFns ...func(o *RoleTrustsOptions)) *RoleTrustsRecon {
	opts := RoleTrustsOptions{}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &RoleTrustsRecon{
		iamClient: iam.NewFromConfig(cfg.AWSConfig),
		opts:      opts,
		account:   cfg.Account,
	}

	r.recon = newRecon[RoleTrust](func() {
		r.runEnumerateService("iam", func() {
			r.enumerateRoleTrusts()
		})
	}, func(o *reconOptions) {
		o.BeforeHook = opts.BeforeHook
		o.AfterRunHook = opts.AfterRunHook
	})

	return r
}

func (rec *RoleTrustsRecon) enumerateRoleTrusts() {
	p := iam.NewListRolesPaginator(rec.iamClient, &iam.ListRolesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO())
		if err != nil {
			rec.addError(err)
			return
		}

		for _, role := range page.Roles {
			var (
				lastUsedDate   time.Time
				lastUsedRegion string
			)

			if role.RoleLastUsed != nil {
				lastUsedDate = aws.ToTime(role.RoleLastUsed.LastUsedDate)
				lastUsedRegion = aws.ToString(role.RoleLastUsed.Region)
			}

			doc, err := reconIam.ConvertToPolicyDocument(aws.ToString(role.AssumeRolePolicyDocument))
			if err != nil {
				rec.addError(err)
				continue
			}

			roleARN := aws.ToString(role.Arn)

			var roleHints []string

		statementLoop:
			for _, statement := range doc.Statements {
				externalID, err := getExternalID(statement)
				if err != nil {
					rec.addError(err)
					continue
				}

				if statement.Effect == reconIam.EffectDeny {
					if !common.SliceContains(roleHints, "HasDeny") {
						roleHints = append(roleHints, "HasDeny")
					}

					continue // TODO Consider further behavior on deny
				}

				for k, v := range statement.Principal {
					for _, principal := range v {
						var hints []string
						copy(hints, roleHints)

						switch k {
						case "Service":
							if strings.HasPrefix(roleARN, fmt.Sprintf("arn:aws:iam::%s:role/aws-service-role/", rec.account)) {
								hints = append(hints, "ServiceLinkRole")
								if rec.opts.IgnoreServiceLinkRoles {
									break statementLoop
								}
							}
						case "AWS":
							if !strings.Contains(string(principal), rec.account) {
								hints = append(hints, "CrossAccount")
								if externalID == "" {
									hints = append(hints, "ConfusedDeputyRisk")
								}
							}
						case "Federated":
							if statement.Action[0] == "sts:AssumeRoleWithSAML" {
								hints = append(hints, "SAML")
							} else if statement.Action[0] == "sts:AssumeRoleWithWebIdentity" {
								hints = append(hints, "OIDC")
							}
						}

						rec.addResult(RoleTrust{
							AWSService:     "IAM",
							RoleName:       aws.ToString(role.RoleName),
							RoleARN:        roleARN,
							CreateDate:     aws.ToTime(role.CreateDate),
							LastUsedDate:   lastUsedDate,
							LastUsedRegion: lastUsedRegion,
							Principal:      k,
							TrustedEntity:  string(principal),
							ExternalID:     externalID,
							Hints:          hints,
						})
					}
				}
			}
		}
	}
}

func getExternalID(statement reconIam.Statement) (string, error) {
	if statement.Condition != nil {
		cond, err := reconIam.ConvertToExternalIDCondition(statement.Condition)
		if err != nil {
			return "", err
		}

		return cond.StringEquals.StsExternalID, nil
	}

	return "", nil
}
