package recon

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewayTypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2Types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnerTypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	appsyncTypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elasticloadbalancingv2Types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/grafana"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/hupe1980/awsrecon/pkg/config"
)

type Visibility string

const (
	VisibilityPublic  Visibility = "public"
	VisibiltyPrivate  Visibility = "private"
	VisibilityUnknown Visibility = "unknown"
)

type EndpointsOptions struct {
	IgnoreServices []string
	BeforeHook     BeforeHookFunc
	AfterRunHook   AfterRunHookFunc
}

type Endpoint struct {
	AWSService string
	Region     string
	Name       string
	Type       string
	Endpoint   string
	Port       int32
	Protocol   string
	Visibility Visibility
	Hints      []string
}

type EndpointsRecon struct {
	*recon[Endpoint]
	apigatewayClient   *apigateway.Client
	apigatewayv2Client *apigatewayv2.Client
	apprunnerClient    *apprunner.Client
	appsyncClient      *appsync.Client
	cloudfrontClient   *cloudfront.Client
	docdbClient        *docdb.Client
	eksClient          *eks.Client
	elbClient          *elasticloadbalancing.Client
	elbv2Client        *elasticloadbalancingv2.Client
	grafanaClient      *grafana.Client
	lambdaClient       *lambda.Client
	lightsailClient    *lightsail.Client
	mqClient           *mq.Client
	opensearchClient   *opensearch.Client
	rdsClient          *rds.Client
	redshiftClient     *redshift.Client
}

func NewEndpointsRecon(cfg *config.Config, optFns ...func(o *EndpointsOptions)) *EndpointsRecon {
	opts := EndpointsOptions{}

	for _, fn := range optFns {
		fn(&opts)
	}

	r := &EndpointsRecon{
		apigatewayClient:   apigateway.NewFromConfig(cfg.AWSConfig),
		apigatewayv2Client: apigatewayv2.NewFromConfig(cfg.AWSConfig),
		apprunnerClient:    apprunner.NewFromConfig(cfg.AWSConfig),
		appsyncClient:      appsync.NewFromConfig(cfg.AWSConfig),
		cloudfrontClient:   cloudfront.NewFromConfig(cfg.AWSConfig),
		docdbClient:        docdb.NewFromConfig(cfg.AWSConfig),
		eksClient:          eks.NewFromConfig(cfg.AWSConfig),
		elbClient:          elasticloadbalancing.NewFromConfig(cfg.AWSConfig),
		elbv2Client:        elasticloadbalancingv2.NewFromConfig(cfg.AWSConfig),
		grafanaClient:      grafana.NewFromConfig(cfg.AWSConfig),
		lambdaClient:       lambda.NewFromConfig(cfg.AWSConfig),
		lightsailClient:    lightsail.NewFromConfig(cfg.AWSConfig),
		mqClient:           mq.NewFromConfig(cfg.AWSConfig),
		opensearchClient:   opensearch.NewFromConfig(cfg.AWSConfig),
		rdsClient:          rds.NewFromConfig(cfg.AWSConfig),
		redshiftClient:     redshift.NewFromConfig(cfg.AWSConfig),
	}

	r.recon = newRecon[Endpoint](func() {
		r.runEnumerateServicePerRegion("apigateway", cfg.Regions, func(region string) {
			r.enumerateAPIGatewayAPIsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("apigatewayv2", cfg.Regions, func(region string) {
			r.enumerateAPIGatewayV2APIsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("apprunner", cfg.Regions, func(region string) {
			r.enumerateApprunnerEndpointsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("appsync", cfg.Regions, func(region string) {
			r.enumerateAppsyncEndpointsPerRegion(region)
		})

		r.runEnumerateService("cloudfront", func() {
			r.enumerateCloudfrontDistributions()
		})

		r.runEnumerateServicePerRegion("docdb", cfg.Regions, func(region string) {
			r.enumerateDocDBClusterPerRegion(region)
		})

		r.runEnumerateServicePerRegion("eks", cfg.Regions, func(region string) {
			r.enumerateEKSClusterPerRegion(region)
		})

		r.runEnumerateServicePerRegion("elb", cfg.Regions, func(region string) {
			r.enumerateELBListenerPerRegion(region)
		})

		r.runEnumerateServicePerRegion("elbv2", cfg.Regions, func(region string) {
			r.enumerateELBv2ListenerPerRegion(region)
		})

		r.runEnumerateServicePerRegion("grafana", cfg.Regions, func(region string) {
			r.enumerateGrafanaEndpointsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("lambda", cfg.Regions, func(region string) {
			r.enumerateLambdaFunctionsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("lightsail", cfg.Regions, func(region string) {
			r.enumerateLightsailEndpointsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("mq", cfg.Regions, func(region string) {
			r.enumerateMQBrokersPerRegion(region)
		})

		r.runEnumerateServicePerRegion("opensearch", cfg.Regions, func(region string) {
			r.enumerateOpensearchDomainsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("rds", cfg.Regions, func(region string) {
			r.enumerateRDSEndpointsPerRegion(region)
		})

		r.runEnumerateServicePerRegion("redshift", cfg.Regions, func(region string) {
			r.enumerateRedshiftEndpointsPerRegion(region)
		})
	}, func(o *reconOptions) {
		o.IgnoreServices = opts.IgnoreServices
		o.BeforeHook = opts.BeforeHook
		o.AfterRunHook = opts.AfterRunHook
	})

	return r
}

func (rec *EndpointsRecon) enumerateAPIGatewayAPIsPerRegion(region string) {
	p := apigateway.NewGetRestApisPaginator(rec.apigatewayClient, &apigateway.GetRestApisInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *apigateway.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, api := range page.Items {
			pr := apigateway.NewGetResourcesPaginator(rec.apigatewayClient, &apigateway.GetResourcesInput{
				RestApiId: api.Id,
			})
			for pr.HasMorePages() {
				resourcePage, err := pr.NextPage(context.TODO(), func(o *apigateway.Options) {
					o.Region = region
				})
				if err != nil {
					rec.addError(err)
					continue
				}

				// TODO: Enumerate custom domain
				if api.DisableExecuteApiEndpoint {
					continue
				}

				getStages, err := rec.apigatewayClient.GetStages(context.TODO(), &apigateway.GetStagesInput{
					RestApiId: api.Id,
				}, func(o *apigateway.Options) {
					o.Region = region
				})
				if err != nil {
					rec.addError(err)
					continue
				}

				for _, stage := range getStages.Item {
					baseEndpoint := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/%s", aws.ToString(api.Id), region, aws.ToString(stage.StageName))

					visibility := VisibilityPublic
					if api.EndpointConfiguration.Types[0] == apigatewayTypes.EndpointTypePrivate {
						visibility = VisibiltyPrivate
					}

					for _, item := range resourcePage.Items {
						if len(item.ResourceMethods) == 0 {
							continue
						}

						for httpMethod := range item.ResourceMethods {
							var hints []string

							if setting, ok := stage.MethodSettings["*/*"]; ok {
								hints = append(hints, fmt.Sprintf("RateLimit_%s", strconv.FormatFloat(setting.ThrottlingRateLimit, 'f', -1, 64)))
								hints = append(hints, fmt.Sprintf("BurstLimit_%d", setting.ThrottlingBurstLimit))
							}

							if stage.WebAclArn != nil {
								hints = append(hints, "WAF")
							} else {
								hints = append(hints, "NoWAF")
							}

							method, err := rec.apigatewayClient.GetMethod(context.TODO(), &apigateway.GetMethodInput{
								RestApiId:  api.Id,
								ResourceId: item.Id,
								HttpMethod: aws.String(httpMethod),
							}, func(o *apigateway.Options) {
								o.Region = region
							})
							if err == nil {
								if aws.ToBool(method.ApiKeyRequired) {
									hints = append(hints, "ApiKeyRequired")
								}

								switch aws.ToString(method.AuthorizationType) {
								case "AWS_IAM":
									hints = append(hints, "IAMAuthorizer")
								case "COGNITO_USER_POOLS":
									hints = append(hints, "CognitoAuthorizer")
								case "CUSTOM":
									hints = append(hints, "CustomAuthorizer")
								default:
									hints = append(hints, "NoAuthorizer")
								}
							} else {
								hints = append(hints, "UnknownApiKeyStatus", "UnknownAuthorizerStatus")
								rec.addError(err)
							}

							rec.addResult(Endpoint{
								AWSService: "APIGateway",
								Region:     region,
								Name:       aws.ToString(api.Name),
								Type:       httpMethod,
								Endpoint:   fmt.Sprintf("%s%s", baseEndpoint, aws.ToString(item.Path)),
								Port:       443,
								Protocol:   "https",
								Visibility: visibility,
								Hints:      hints,
							})
						}
					}
				}
			}
		}
	}
}

func (rec *EndpointsRecon) enumerateAPIGatewayV2APIsPerRegion(region string) {
	var paginationControl *string

	for {
		apis, err := rec.apigatewayv2Client.GetApis(context.TODO(), &apigatewayv2.GetApisInput{
			NextToken: paginationControl,
		}, func(o *apigatewayv2.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, api := range apis.Items {
			var paginationControl2 *string

			for {
				routes, err := rec.apigatewayv2Client.GetRoutes(context.TODO(), &apigatewayv2.GetRoutesInput{
					ApiId:     api.ApiId,
					NextToken: paginationControl2,
				}, func(o *apigatewayv2.Options) {
					o.Region = region
				})
				if err != nil {
					rec.addError(err)
					continue
				}

				for _, route := range routes.Items {
					var hints []string

					routeKey := aws.ToString(route.RouteKey)

					var (
						path         string
						endpointType string
					)

					if len(strings.Fields(routeKey)) == 2 {
						endpointType = strings.Fields(routeKey)[0]
						path = strings.Fields(routeKey)[1]
					} else {
						endpointType = "WSS"
						hints = append(hints, "Websocket")
					}

					if route.ApiKeyRequired {
						hints = append(hints, "ApiKeyRequired")
					}

					if route.AuthorizationType == apigatewayv2Types.AuthorizationTypeNone {
						hints = append(hints, "NoAuthorization")
					} else {
						// TODO
						hints = append(hints, string(route.AuthorizationType))
					}

					endpoint := fmt.Sprintf("%s%s", aws.ToString(api.ApiEndpoint), path)

					rec.addResult(Endpoint{
						AWSService: "APIGatewayv2",
						Region:     region,
						Name:       aws.ToString(api.Name),
						Type:       endpointType,
						Endpoint:   endpoint,
						Port:       443,
						Protocol:   "https",
						Visibility: VisibilityPublic,
						Hints:      hints,
					})
				}

				if routes.NextToken != nil {
					paginationControl2 = routes.NextToken
				} else {
					break
				}
			}
		}

		if apis.NextToken != nil {
			paginationControl = apis.NextToken
		} else {
			break
		}
	}
}

func (rec *EndpointsRecon) enumerateApprunnerEndpointsPerRegion(region string) {
	p := apprunner.NewListServicesPaginator(rec.apprunnerClient, &apprunner.ListServicesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *apprunner.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.ServiceSummaryList {
			svc, err := rec.apprunnerClient.DescribeService(context.TODO(), &apprunner.DescribeServiceInput{
				ServiceArn: item.ServiceArn,
			}, func(o *apprunner.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			visibility := VisibiltyPrivate
			if svc.Service.NetworkConfiguration.EgressConfiguration.EgressType == apprunnerTypes.EgressTypeDefault {
				visibility = VisibilityPublic
			}

			rec.addResult(Endpoint{
				AWSService: "Apprunner",
				Region:     region,
				Name:       fmt.Sprintf("%s [distribution]", aws.ToString(item.ServiceName)),
				Type:       "URL",
				Endpoint:   fmt.Sprintf("https://%s", aws.ToString(item.ServiceUrl)),
				Port:       443,
				Protocol:   "https",
				Visibility: visibility,
			})
		}
	}
}

func (rec *EndpointsRecon) enumerateAppsyncEndpointsPerRegion(region string) {
	output, err := rec.appsyncClient.ListGraphqlApis(context.TODO(), &appsync.ListGraphqlApisInput{}, func(o *appsync.Options) {
		o.Region = region
	})
	if err != nil {
		rec.addError(err)
		return
	}

	for _, item := range output.GraphqlApis {
		var hints []string

		switch item.AuthenticationType {
		case appsyncTypes.AuthenticationTypeAwsIam:
			hints = append(hints, "IAMAuthentication")
		case appsyncTypes.AuthenticationTypeAmazonCognitoUserPools:
			hints = append(hints, "CognitoAuthentication")
		case appsyncTypes.AuthenticationTypeApiKey:
			hints = append(hints, "ApiKeyAuthentication")
		case appsyncTypes.AuthenticationTypeAwsLambda:
			hints = append(hints, "AwsLAmbdaAuthentication")
		case appsyncTypes.AuthenticationTypeOpenidConnect:
			hints = append(hints, "OpenidAuthentication")
		default:
			hints = append(hints, "NoAuthentication")
		}

		if item.WafWebAclArn != nil {
			hints = append(hints, "WAF")
		} else {
			hints = append(hints, "NoWAF")
		}

		for endpointType, uri := range item.Uris {
			protocol := "https"
			if endpointType == "REALTIME" {
				protocol = "wss"
			}

			rec.addResult(Endpoint{
				AWSService: "Appsync",
				Region:     region,
				Name:       aws.ToString(item.Name),
				Type:       endpointType,
				Endpoint:   uri,
				Port:       443,
				Protocol:   protocol,
				Visibility: VisibilityPublic,
				Hints:      hints,
			})
		}
	}
}

func (rec *EndpointsRecon) enumerateCloudfrontDistributions() {
	p := cloudfront.NewListDistributionsPaginator(rec.cloudfrontClient, &cloudfront.ListDistributionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO())
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.DistributionList.Items {
			var hints []string

			if aws.ToString(item.WebACLId) != "" {
				hints = append(hints, "WAF")
			} else {
				hints = append(hints, "NoWAF")
			}

			if !aws.ToBool(item.Enabled) {
				hints = append(hints, "Disabled")
			}

			if aws.ToBool(item.IsIPV6Enabled) {
				hints = append(hints, "IPV6")
			}

			if len(item.Restrictions.GeoRestriction.Items) > 0 {
				hints = append(hints, "GeoRestriction")
			}

			hints = append(hints, fmt.Sprintf("Min%s", item.ViewerCertificate.MinimumProtocolVersion))

			hints = append(hints, string(item.PriceClass))

			rec.addResult(Endpoint{
				AWSService: "Cloudfront",
				Region:     "global",
				Name:       aws.ToString(item.Id),
				Type:       "Distribution",
				Endpoint:   fmt.Sprintf("https://%s", aws.ToString(item.DomainName)),
				Port:       443,
				Protocol:   "https",
				Visibility: VisibilityPublic,
				Hints:      hints,
			})

			for _, alias := range item.Aliases.Items {
				rec.addResult(Endpoint{
					AWSService: "Cloudfront",
					Region:     "global",
					Name:       aws.ToString(item.Id),
					Type:       "Alias",
					Endpoint:   fmt.Sprintf("https://%s", alias),
					Port:       443,
					Protocol:   "https",
					Visibility: VisibilityPublic,
					Hints:      hints,
				})
			}

			for _, origin := range item.Origins.Items {
				var originHints []string

				if origin.S3OriginConfig != nil && origin.S3OriginConfig.OriginAccessIdentity != nil {
					originHints = append(originHints, "OAI")
				}

				if origin.CustomHeaders != nil && aws.ToInt32(origin.CustomHeaders.Quantity) > 0 {
					originHints = append(originHints, "CustomHeaders")

					for _, h := range origin.CustomHeaders.Items {
						name := strings.ToLower(aws.ToString(h.HeaderName))

						if name == "x-api-key" {
							originHints = append(originHints, "X-API-KEY")
						} else if name == "authorization" {
							originHints = append(originHints, "Authorization")
						}
					}
				} else {
					originHints = append(originHints, "NoCustomHeaders")
				}

				rec.addResult(Endpoint{
					AWSService: "Cloudfront",
					Region:     "global",
					Name:       aws.ToString(item.Id),
					Type:       "Origin",
					Endpoint:   fmt.Sprintf("https://%s/%s", aws.ToString(origin.DomainName), aws.ToString(origin.OriginPath)),
					Port:       443,
					Protocol:   "https",
					Visibility: VisibilityUnknown,
					Hints:      originHints,
				})
			}
		}
	}
}

func (rec *EndpointsRecon) enumerateDocDBClusterPerRegion(region string) {
	p := docdb.NewDescribeDBClustersPaginator(rec.docdbClient, &docdb.DescribeDBClustersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *docdb.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, cluster := range page.DBClusters {
			var hints []string
			if cluster.StorageEncrypted {
				hints = append(hints, "Encrypted")
			} else {
				hints = append(hints, "NotEncrypted")
			}

			if cluster.DeletionProtection {
				hints = append(hints, "DeletionProtection")
			} else {
				hints = append(hints, "NoDeletionProtection")
			}

			rec.addResult(Endpoint{
				AWSService: "DocDB",
				Region:     region,
				Name:       aws.ToString(cluster.DBClusterIdentifier),
				Type:       "Endpoint",
				Endpoint:   aws.ToString(cluster.Endpoint),
				Port:       aws.ToInt32(cluster.Port),
				Protocol:   "https",
				Visibility: VisibiltyPrivate,
				Hints:      hints,
			})

			if cluster.ReaderEndpoint != nil {
				rec.addResult(Endpoint{
					AWSService: "DocDB",
					Region:     region,
					Name:       aws.ToString(cluster.DBClusterIdentifier),
					Type:       "ReaderEndpoint",
					Endpoint:   aws.ToString(cluster.ReaderEndpoint),
					Port:       aws.ToInt32(cluster.Port),
					Protocol:   "https",
					Visibility: VisibiltyPrivate,
					Hints:      hints,
				})
			}
		}
	}
}

func (rec *EndpointsRecon) enumerateEKSClusterPerRegion(region string) {
	p := eks.NewListClustersPaginator(rec.eksClient, &eks.ListClustersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *eks.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for i := range page.Clusters {
			output, err := rec.eksClient.DescribeCluster(context.TODO(), &eks.DescribeClusterInput{
				Name: &page.Clusters[i],
			}, func(o *eks.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			visibility := VisibiltyPrivate

			if output.Cluster.ResourcesVpcConfig.EndpointPublicAccess {
				if output.Cluster.ResourcesVpcConfig.PublicAccessCidrs[0] == "0.0.0.0/0" {
					visibility = VisibilityPublic
				}
			}

			rec.addResult(Endpoint{
				AWSService: "EKS",
				Region:     region,
				Name:       aws.ToString(output.Cluster.Name),
				Type:       "API Server",
				Endpoint:   aws.ToString(output.Cluster.Endpoint),
				Port:       443,
				Protocol:   "https",
				Visibility: visibility,
			})
		}
	}
}

func (rec *EndpointsRecon) enumerateELBListenerPerRegion(region string) {
	p := elasticloadbalancing.NewDescribeLoadBalancersPaginator(rec.elbClient, &elasticloadbalancing.DescribeLoadBalancersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *elasticloadbalancing.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.LoadBalancerDescriptions {
			endpoint := aws.ToString(item.DNSName)

			visibility := VisibiltyPrivate
			if aws.ToString(item.Scheme) == "internet-facing" {
				visibility = VisibilityPublic
			}

			for _, l := range item.ListenerDescriptions {
				port := l.Listener.LoadBalancerPort

				protocol := aws.ToString(l.Listener.Protocol)
				if protocol == "HTTPS" {
					endpoint = fmt.Sprintf("https://%s:%s", endpoint, strconv.Itoa(int(port)))
				} else if protocol == "HTTP" {
					endpoint = fmt.Sprintf("http://%s:%s", endpoint, strconv.Itoa(int(port)))
				}

				rec.addResult(Endpoint{
					AWSService: "ELB",
					Region:     region,
					Name:       aws.ToString(item.LoadBalancerName),
					Type:       "Listener",
					Endpoint:   endpoint,
					Port:       port,
					Protocol:   protocol,
					Visibility: visibility,
				})
			}
		}
	}
}

func (rec *EndpointsRecon) enumerateELBv2ListenerPerRegion(region string) {
	p := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(rec.elbv2Client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *elasticloadbalancingv2.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.LoadBalancers {
			visibility := VisibiltyPrivate
			if item.Scheme == elasticloadbalancingv2Types.LoadBalancerSchemeEnumInternetFacing {
				visibility = VisibilityPublic
			}

			endpoint := aws.ToString(item.DNSName)

			pl := elasticloadbalancingv2.NewDescribeListenersPaginator(rec.elbv2Client, &elasticloadbalancingv2.DescribeListenersInput{
				LoadBalancerArn: item.LoadBalancerArn,
			})

			listenerPage, err := pl.NextPage(context.TODO())
			if err != nil {
				rec.addError(err)
				continue
			}

			for _, l := range listenerPage.Listeners {
				port := aws.ToInt32(l.Port)

				if l.Protocol == elasticloadbalancingv2Types.ProtocolEnumHttps {
					endpoint = fmt.Sprintf("https://%s:%s", endpoint, strconv.Itoa(int(port)))
				} else if l.Protocol == elasticloadbalancingv2Types.ProtocolEnumHttp {
					endpoint = fmt.Sprintf("http://%s:%s", endpoint, strconv.Itoa(int(port)))
				}

				rec.addResult(Endpoint{
					AWSService: "ELBv2",
					Region:     region,
					Name:       aws.ToString(item.LoadBalancerName),
					Type:       "Listener",
					Endpoint:   endpoint,
					Port:       port,
					Protocol:   string(l.Protocol),
					Visibility: visibility,
				})
			}
		}
	}
}

func (rec *EndpointsRecon) enumerateGrafanaEndpointsPerRegion(region string) {
	p := grafana.NewListWorkspacesPaginator(rec.grafanaClient, &grafana.ListWorkspacesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *grafana.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, workspace := range page.Workspaces {
			rec.addResult(Endpoint{
				AWSService: "Grafana",
				Region:     region,
				Name:       aws.ToString(workspace.Name),
				Type:       "Console",
				Endpoint:   aws.ToString(workspace.Endpoint),
				Port:       443,
				Protocol:   "https",
				Visibility: VisibilityUnknown,
			})
		}
	}
}

func (rec *EndpointsRecon) enumerateMQBrokersPerRegion(region string) {
	p := mq.NewListBrokersPaginator(rec.mqClient, &mq.ListBrokersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *mq.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, item := range page.BrokerSummaries {
			b, err := rec.mqClient.DescribeBroker(context.TODO(), &mq.DescribeBrokerInput{
				BrokerId: item.BrokerId,
			}, func(o *mq.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			visibility := VisibiltyPrivate
			if b.PubliclyAccessible {
				visibility = VisibilityPublic
			}

			rec.addResult(Endpoint{
				AWSService: "Amazon MQ",
				Name:       aws.ToString(b.BrokerName),
				Region:     region,
				Type:       "Console",
				Endpoint:   aws.ToString(b.BrokerInstances[0].ConsoleURL),
				Port:       443,
				Protocol:   "https",
				Visibility: visibility,
			})
		}
	}
}

func (rec *EndpointsRecon) enumerateOpensearchDomainsPerRegion(region string) {
	output, err := rec.opensearchClient.ListDomainNames(context.TODO(), &opensearch.ListDomainNamesInput{}, func(o *opensearch.Options) {
		o.Region = region
	})
	if err != nil {
		rec.addError(err)
		return
	}

	for _, item := range output.DomainNames {
		dn, err := rec.opensearchClient.DescribeDomain(context.TODO(), &opensearch.DescribeDomainInput{
			DomainName: item.DomainName,
		}, func(o *opensearch.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			continue
		}

		var hints []string

		if aws.ToBool(dn.DomainStatus.CognitoOptions.Enabled) {
			hints = append(hints, "CognitoEnabled")
		}

		hints = append(hints, aws.ToString(dn.DomainStatus.EngineVersion))

		endpoint := aws.ToString(dn.DomainStatus.Endpoint)

		rec.addResult(Endpoint{
			AWSService: "Opensearch",
			Name:       aws.ToString(item.DomainName),
			Region:     region,
			Type:       "API",
			Endpoint:   fmt.Sprintf("https://%s", endpoint),
			Port:       443,
			Protocol:   "https",
			Visibility: VisibilityUnknown,
			Hints:      hints,
		})

		rec.addResult(Endpoint{
			AWSService: "Opensearch",
			Name:       aws.ToString(item.DomainName),
			Region:     region,
			Type:       "Kibana",
			Endpoint:   fmt.Sprintf("https://%s/_plugin/kibana/", endpoint),
			Port:       443,
			Protocol:   "https",
			Visibility: VisibilityUnknown,
			Hints:      hints,
		})
	}
}

func (rec *EndpointsRecon) enumerateLambdaFunctionsPerRegion(region string) {
	p := lambda.NewListFunctionsPaginator(rec.lambdaClient, &lambda.ListFunctionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *lambda.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, function := range page.Functions {
			output, err := rec.lambdaClient.GetFunctionUrlConfig(context.TODO(), &lambda.GetFunctionUrlConfigInput{
				FunctionName: function.FunctionArn,
			}, func(o *lambda.Options) {
				o.Region = region
			})
			if err != nil {
				rec.addError(err)
				continue
			}

			visibility := VisibiltyPrivate
			if output.AuthType == lambdaTypes.FunctionUrlAuthTypeNone {
				visibility = VisibilityPublic
			}

			rec.addResult(Endpoint{
				AWSService: "Lambda",
				Name:       aws.ToString(function.FunctionName),
				Region:     region,
				Type:       "URL",
				Endpoint:   aws.ToString(output.FunctionUrl),
				Port:       443,
				Protocol:   "https",
				Visibility: visibility,
			})
		}
	}
}

func (rec *EndpointsRecon) enumerateLightsailEndpointsPerRegion(region string) {
	output, err := rec.lightsailClient.GetContainerServices(context.TODO(), &lightsail.GetContainerServicesInput{}, func(o *lightsail.Options) {
		o.Region = region
	})
	if err != nil {
		rec.addError(err)
		return
	}

	for _, item := range output.ContainerServices {
		rec.addResult(Endpoint{
			AWSService: "Lightsail",
			Name:       aws.ToString(item.ContainerServiceName),
			Region:     region,
			Type:       "URL",
			Endpoint:   aws.ToString(item.Url),
			Port:       443,
			Protocol:   "https",
			Visibility: VisibilityPublic,
		})
	}
}

func (rec *EndpointsRecon) enumerateRDSEndpointsPerRegion(region string) {
	p := rds.NewDescribeDBInstancesPaginator(rec.rdsClient, &rds.DescribeDBInstancesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *rds.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, instance := range page.DBInstances {
			if instance.Endpoint != nil {
				visibility := VisibiltyPrivate
				if instance.PubliclyAccessible {
					visibility = VisibilityPublic
				}

				var hints []string
				if instance.StorageEncrypted {
					hints = append(hints, "Encrypted")
				} else {
					hints = append(hints, "NotEncrypted")
				}

				if instance.DeletionProtection {
					hints = append(hints, "DeletionProtection")
				} else {
					hints = append(hints, "NoDeletionProtection")
				}

				rec.addResult(Endpoint{
					AWSService: "RDS",
					Region:     region,
					Name:       aws.ToString(instance.DBInstanceIdentifier),
					Type:       "DNS",
					Endpoint:   aws.ToString(instance.Endpoint.Address),
					Port:       instance.Endpoint.Port,
					Protocol:   aws.ToString(instance.Engine),
					Visibility: visibility,
					Hints:      hints,
				})
			}
		}
	}
}

func (rec *EndpointsRecon) enumerateRedshiftEndpointsPerRegion(region string) {
	p := redshift.NewDescribeClustersPaginator(rec.redshiftClient, &redshift.DescribeClustersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(context.TODO(), func(o *redshift.Options) {
			o.Region = region
		})
		if err != nil {
			rec.addError(err)
			return
		}

		for _, cluster := range page.Clusters {
			visibility := VisibiltyPrivate
			if cluster.PubliclyAccessible {
				visibility = VisibilityPublic
			}

			rec.addResult(Endpoint{
				AWSService: "Redshift",
				Region:     region,
				Name:       aws.ToString(cluster.DBName),
				Type:       "DNS",
				Endpoint:   aws.ToString(cluster.Endpoint.Address),
				Port:       cluster.Endpoint.Port,
				Protocol:   "https",
				Visibility: visibility,
			})
		}
	}
}
