package cfn

import (
	"strings"

	"github.com/hupe1980/awsrecon/pkg/cloudformation"
	"github.com/hupe1980/awsrecon/pkg/common"
)

type Result struct {
	ID string
}

type Rule interface {
	Audit(resource *cloudformation.Resource) ([]Result, error)
}

type CloudformationAuthenticationRule struct{}

func (rule CloudformationAuthenticationRule) Audit(resource *cloudformation.Resource) ([]Result, error) {
	if resource.Metadata != nil {
		if authMeta, ok := resource.Metadata["AWS::CloudFormation::Authentication"]; ok {
			if authMap, ok := authMeta.(map[string]interface{}); ok {
				for _, v := range authMap {
					keys := common.MapKeys(v.(map[string]interface{}))
					for _, k := range keys {
						if k == "accessKeyId" || k == "password" || k == "secretKey" {
							return []Result{{ID: "CloudformationAuthentication"}}, nil
						}
					}
				}
			}
		}
	}

	return nil, nil
}

type PasswordProperty struct {
	PropertyName    string
	SubPropertyName string
}

var PasswordPropertyResources = map[string][]PasswordProperty{
	"AWS::Amplify::App":                     {{PropertyName: "OauthToken"}, {PropertyName: "AccessToken"}, {PropertyName: "BasicAuthConfig", SubPropertyName: "Password"}},
	"AWS::Amplify::Branch":                  {{PropertyName: "BasicAuthConfig", SubPropertyName: "Password"}},
	"AWS::AppStream::DirectoryConfig":       {{PropertyName: "ServiceAccountCredentials", SubPropertyName: "AccountPassword"}},
	"AWS::CodePipeline::Webhook":            {{PropertyName: "AuthenticationConfiguration", SubPropertyName: "SecretToken"}},
	"AWS::DMS::Endpoint":                    {{PropertyName: "Password"}, {PropertyName: "MongoDbSettings", SubPropertyName: "Password"}},
	"AWS::DirectoryService::MicrosoftAD":    {{PropertyName: "Password"}},
	"AWS::DirectoryService::SimpleAD":       {{PropertyName: "Password"}},
	"AWS::DocDB::DBCluster":                 {{PropertyName: "MasterUserPassword"}},
	"AWS::EMR::Cluster":                     {{PropertyName: "KerberosAttributes", SubPropertyName: "ADDomainJoinPassword"}, {PropertyName: "KerberosAttributes", SubPropertyName: "CrossRealmTrustPrincipalPassword"}, {PropertyName: "KerberosAttributes", SubPropertyName: "KdcAdminPassword"}},
	"AWS::ElastiCache::ReplicationGroup":    {{PropertyName: "AuthToken"}},
	"AWS::IAM::User":                        {{PropertyName: "LoginProfile", SubPropertyName: "Password"}},
	"AWS::Lambda::Permission":               {{PropertyName: "EventSourceToken"}},
	"AWS::OpsWorks::App":                    {{PropertyName: "AppSource", SubPropertyName: "Password"}, {PropertyName: "SslConfiguration", SubPropertyName: "PrivateKey"}},
	"AWS::OpsWorks::Stack":                  {{PropertyName: "CustomCookbooksSource", SubPropertyName: "Password"}, {PropertyName: "RdsDbInstances", SubPropertyName: "DbPassword"}},
	"AWS::Pinpoint::APNSChannel":            {{PropertyName: "PrivateKey"}, {PropertyName: "TokenKey"}},
	"AWS::Pinpoint::APNSSandboxChannel":     {{PropertyName: "PrivateKey"}, {PropertyName: "TokenKey"}},
	"AWS::Pinpoint::APNSVoipChannel":        {{PropertyName: "PrivateKey"}, {PropertyName: "TokenKey"}},
	"AWS::Pinpoint::APNSVoipSandboxChannel": {{PropertyName: "PrivateKey"}, {PropertyName: "TokenKey"}},
	"AWS::RDS::DBCluster":                   {{PropertyName: "MasterUserPassword"}},
	"AWS::RDS::DBInstance":                  {{PropertyName: "MasterUserPassword"}},
	"AWS::Redshift::Cluster":                {{PropertyName: "MasterUserPassword"}},
}

type PasswordPropertyRule struct{}

func (rule PasswordPropertyRule) Audit(resource *cloudformation.Resource) ([]Result, error) {
	if conf, ok := PasswordPropertyResources[resource.Type]; ok {
		for _, c := range conf {
			if prop, ok := resource.Properties[c.PropertyName]; ok {
				switch v := prop.(type) {
				case string:
					if isInsecureString(v) {
						return []Result{{ID: "PasswordProperty"}}, nil
					}
				case map[string]interface{}:
					if subprop, ok := v[c.SubPropertyName]; ok {
						if isInsecureString(subprop) {
							return []Result{{ID: "PasswordProperty"}}, nil
						}
					}
				}
			}
		}
	}

	return nil, nil
}

func isInsecureString(value any) bool {
	switch v := value.(type) {
	case string:
		if strings.HasPrefix(v, "{{resolve:secretsmanager:") || strings.HasPrefix(v, "{{resolve:ssm-secure:") {
			return false
		}

		return true
	}

	return false
}
