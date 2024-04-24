# coding=utf-8
# *** WARNING: this file was generated by pulumi-gen-awsx. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from ._enums import *
import pulumi_aws

__all__ = [
    'NatGatewayConfigurationArgs',
    'SubnetSpecArgs',
    'VpcEndpointSpecArgs',
]

@pulumi.input_type
class NatGatewayConfigurationArgs:
    def __init__(__self__, *,
                 strategy: 'NatGatewayStrategy',
                 elastic_ip_allocation_ids: Optional[Sequence[pulumi.Input[str]]] = None):
        """
        Configuration for NAT Gateways.
        :param 'NatGatewayStrategy' strategy: The strategy for deploying NAT Gateways.
        :param Sequence[pulumi.Input[str]] elastic_ip_allocation_ids: A list of EIP allocation IDs to assign to the NAT Gateways. Optional. If specified, the number of supplied values must match the chosen strategy (either one, or the number of availability zones).
        """
        pulumi.set(__self__, "strategy", strategy)
        if elastic_ip_allocation_ids is not None:
            pulumi.set(__self__, "elastic_ip_allocation_ids", elastic_ip_allocation_ids)

    @property
    @pulumi.getter
    def strategy(self) -> 'NatGatewayStrategy':
        """
        The strategy for deploying NAT Gateways.
        """
        return pulumi.get(self, "strategy")

    @strategy.setter
    def strategy(self, value: 'NatGatewayStrategy'):
        pulumi.set(self, "strategy", value)

    @property
    @pulumi.getter(name="elasticIpAllocationIds")
    def elastic_ip_allocation_ids(self) -> Optional[Sequence[pulumi.Input[str]]]:
        """
        A list of EIP allocation IDs to assign to the NAT Gateways. Optional. If specified, the number of supplied values must match the chosen strategy (either one, or the number of availability zones).
        """
        return pulumi.get(self, "elastic_ip_allocation_ids")

    @elastic_ip_allocation_ids.setter
    def elastic_ip_allocation_ids(self, value: Optional[Sequence[pulumi.Input[str]]]):
        pulumi.set(self, "elastic_ip_allocation_ids", value)


@pulumi.input_type
class SubnetSpecArgs:
    def __init__(__self__, *,
                 type: 'SubnetType',
                 cidr_blocks: Optional[Sequence[str]] = None,
                 cidr_mask: Optional[int] = None,
                 name: Optional[str] = None,
                 size: Optional[int] = None,
                 tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[str]]]] = None):
        """
        Configuration for a VPC subnet.
        :param 'SubnetType' type: The type of subnet.
        :param Sequence[str] cidr_blocks: An optional list of CIDR blocks to assign to the subnet spec for each AZ. If specified, the count must match the number of AZs being used for the VPC, and must also be specified for all other subnet specs.
        :param int cidr_mask: The netmask for the subnet's CIDR block. This is optional, the default value is inferred from the `cidrMask`, `cidrBlocks` or based on an even distribution of available space from the VPC's CIDR block after being divided evenly by availability zone.
        :param str name: The subnet's name. Will be templated upon creation.
        :param int size: Optional size of the subnet's CIDR block - the number of hosts. This value must be a power of 2 (e.g. 256, 512, 1024, etc.). This is optional, the default value is inferred from the `cidrMask`, `cidrBlocks` or based on an even distribution of available space from the VPC's CIDR block after being divided evenly by availability zone.
        :param pulumi.Input[Mapping[str, pulumi.Input[str]]] tags: A map of tags to assign to the resource.
        """
        pulumi.set(__self__, "type", type)
        if cidr_blocks is not None:
            pulumi.set(__self__, "cidr_blocks", cidr_blocks)
        if cidr_mask is not None:
            pulumi.set(__self__, "cidr_mask", cidr_mask)
        if name is not None:
            pulumi.set(__self__, "name", name)
        if size is not None:
            pulumi.set(__self__, "size", size)
        if tags is not None:
            pulumi.set(__self__, "tags", tags)

    @property
    @pulumi.getter
    def type(self) -> 'SubnetType':
        """
        The type of subnet.
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: 'SubnetType'):
        pulumi.set(self, "type", value)

    @property
    @pulumi.getter(name="cidrBlocks")
    def cidr_blocks(self) -> Optional[Sequence[str]]:
        """
        An optional list of CIDR blocks to assign to the subnet spec for each AZ. If specified, the count must match the number of AZs being used for the VPC, and must also be specified for all other subnet specs.
        """
        return pulumi.get(self, "cidr_blocks")

    @cidr_blocks.setter
    def cidr_blocks(self, value: Optional[Sequence[str]]):
        pulumi.set(self, "cidr_blocks", value)

    @property
    @pulumi.getter(name="cidrMask")
    def cidr_mask(self) -> Optional[int]:
        """
        The netmask for the subnet's CIDR block. This is optional, the default value is inferred from the `cidrMask`, `cidrBlocks` or based on an even distribution of available space from the VPC's CIDR block after being divided evenly by availability zone.
        """
        return pulumi.get(self, "cidr_mask")

    @cidr_mask.setter
    def cidr_mask(self, value: Optional[int]):
        pulumi.set(self, "cidr_mask", value)

    @property
    @pulumi.getter
    def name(self) -> Optional[str]:
        """
        The subnet's name. Will be templated upon creation.
        """
        return pulumi.get(self, "name")

    @name.setter
    def name(self, value: Optional[str]):
        pulumi.set(self, "name", value)

    @property
    @pulumi.getter
    def size(self) -> Optional[int]:
        """
        Optional size of the subnet's CIDR block - the number of hosts. This value must be a power of 2 (e.g. 256, 512, 1024, etc.). This is optional, the default value is inferred from the `cidrMask`, `cidrBlocks` or based on an even distribution of available space from the VPC's CIDR block after being divided evenly by availability zone.
        """
        return pulumi.get(self, "size")

    @size.setter
    def size(self, value: Optional[int]):
        pulumi.set(self, "size", value)

    @property
    @pulumi.getter
    def tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[str]]]]:
        """
        A map of tags to assign to the resource.
        """
        return pulumi.get(self, "tags")

    @tags.setter
    def tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[str]]]]):
        pulumi.set(self, "tags", value)


@pulumi.input_type
class VpcEndpointSpecArgs:
    def __init__(__self__, *,
                 service_name: str,
                 auto_accept: Optional[bool] = None,
                 dns_options: Optional[pulumi.Input['pulumi_aws.ec2.VpcEndpointDnsOptionsArgs']] = None,
                 ip_address_type: Optional[pulumi.Input[str]] = None,
                 policy: Optional[pulumi.Input[str]] = None,
                 private_dns_enabled: Optional[bool] = None,
                 route_table_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 security_group_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 subnet_ids: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]] = None,
                 tags: Optional[pulumi.Input[Mapping[str, pulumi.Input[str]]]] = None,
                 vpc_endpoint_type: Optional[pulumi.Input[str]] = None):
        """
        Provides a VPC Endpoint resource.

        > **NOTE on VPC Endpoints and VPC Endpoint Associations:** The provider provides both standalone VPC Endpoint Associations for
        Route Tables - (an association between a VPC endpoint and a single `route_table_id`),
        Security Groups - (an association between a VPC endpoint and a single `security_group_id`),
        and Subnets - (an association between a VPC endpoint and a single `subnet_id`) and
        a VPC Endpoint resource with `route_table_ids` and `subnet_ids` attributes.
        Do not use the same resource ID in both a VPC Endpoint resource and a VPC Endpoint Association resource.
        Doing so will cause a conflict of associations and will overwrite the association.

        ## Example Usage

        ### Basic

        <!--Start PulumiCodeChooser -->
        ```typescript
        import * as pulumi from "@pulumi/pulumi";
        import * as aws from "@pulumi/aws";

        const s3 = new aws.ec2.VpcEndpoint("s3", {
            vpcId: main.id,
            serviceName: "com.amazonaws.us-west-2.s3",
        });
        ```
        ```python
        import pulumi
        import pulumi_aws as aws

        s3 = aws.ec2.VpcEndpoint("s3",
            vpc_id=main["id"],
            service_name="com.amazonaws.us-west-2.s3")
        ```
        ```csharp
        using System.Collections.Generic;
        using System.Linq;
        using Pulumi;
        using Aws = Pulumi.Aws;

        return await Deployment.RunAsync(() => 
        {
            var s3 = new Aws.Ec2.VpcEndpoint("s3", new()
            {
                VpcId = main.Id,
                ServiceName = "com.amazonaws.us-west-2.s3",
            });

        });
        ```
        ```go
        package main

        import (
        	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
        	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
        )

        func main() {
        	pulumi.Run(func(ctx *pulumi.Context) error {
        		_, err := ec2.NewVpcEndpoint(ctx, "s3", &ec2.VpcEndpointArgs{
        			VpcId:       pulumi.Any(main.Id),
        			ServiceName: pulumi.String("com.amazonaws.us-west-2.s3"),
        		})
        		if err != nil {
        			return err
        		}
        		return nil
        	})
        }
        ```
        ```java
        package generated_program;

        import com.pulumi.Context;
        import com.pulumi.Pulumi;
        import com.pulumi.core.Output;
        import com.pulumi.aws.ec2.VpcEndpoint;
        import com.pulumi.aws.ec2.VpcEndpointArgs;
        import java.util.List;
        import java.util.ArrayList;
        import java.util.Map;
        import java.io.File;
        import java.nio.file.Files;
        import java.nio.file.Paths;

        public class App {
            public static void main(String[] args) {
                Pulumi.run(App::stack);
            }

            public static void stack(Context ctx) {
                var s3 = new VpcEndpoint("s3", VpcEndpointArgs.builder()        
                    .vpcId(main.id())
                    .serviceName("com.amazonaws.us-west-2.s3")
                    .build());

            }
        }
        ```
        ```yaml
        resources:
          s3:
            type: aws:ec2:VpcEndpoint
            properties:
              vpcId: ${main.id}
              serviceName: com.amazonaws.us-west-2.s3
        ```
        <!--End PulumiCodeChooser -->

        ### Basic w/ Tags

        <!--Start PulumiCodeChooser -->
        ```typescript
        import * as pulumi from "@pulumi/pulumi";
        import * as aws from "@pulumi/aws";

        const s3 = new aws.ec2.VpcEndpoint("s3", {
            vpcId: main.id,
            serviceName: "com.amazonaws.us-west-2.s3",
            tags: {
                Environment: "test",
            },
        });
        ```
        ```python
        import pulumi
        import pulumi_aws as aws

        s3 = aws.ec2.VpcEndpoint("s3",
            vpc_id=main["id"],
            service_name="com.amazonaws.us-west-2.s3",
            tags={
                "Environment": "test",
            })
        ```
        ```csharp
        using System.Collections.Generic;
        using System.Linq;
        using Pulumi;
        using Aws = Pulumi.Aws;

        return await Deployment.RunAsync(() => 
        {
            var s3 = new Aws.Ec2.VpcEndpoint("s3", new()
            {
                VpcId = main.Id,
                ServiceName = "com.amazonaws.us-west-2.s3",
                Tags = 
                {
                    { "Environment", "test" },
                },
            });

        });
        ```
        ```go
        package main

        import (
        	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
        	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
        )

        func main() {
        	pulumi.Run(func(ctx *pulumi.Context) error {
        		_, err := ec2.NewVpcEndpoint(ctx, "s3", &ec2.VpcEndpointArgs{
        			VpcId:       pulumi.Any(main.Id),
        			ServiceName: pulumi.String("com.amazonaws.us-west-2.s3"),
        			Tags: pulumi.StringMap{
        				"Environment": pulumi.String("test"),
        			},
        		})
        		if err != nil {
        			return err
        		}
        		return nil
        	})
        }
        ```
        ```java
        package generated_program;

        import com.pulumi.Context;
        import com.pulumi.Pulumi;
        import com.pulumi.core.Output;
        import com.pulumi.aws.ec2.VpcEndpoint;
        import com.pulumi.aws.ec2.VpcEndpointArgs;
        import java.util.List;
        import java.util.ArrayList;
        import java.util.Map;
        import java.io.File;
        import java.nio.file.Files;
        import java.nio.file.Paths;

        public class App {
            public static void main(String[] args) {
                Pulumi.run(App::stack);
            }

            public static void stack(Context ctx) {
                var s3 = new VpcEndpoint("s3", VpcEndpointArgs.builder()        
                    .vpcId(main.id())
                    .serviceName("com.amazonaws.us-west-2.s3")
                    .tags(Map.of("Environment", "test"))
                    .build());

            }
        }
        ```
        ```yaml
        resources:
          s3:
            type: aws:ec2:VpcEndpoint
            properties:
              vpcId: ${main.id}
              serviceName: com.amazonaws.us-west-2.s3
              tags:
                Environment: test
        ```
        <!--End PulumiCodeChooser -->

        ### Interface Endpoint Type

        <!--Start PulumiCodeChooser -->
        ```typescript
        import * as pulumi from "@pulumi/pulumi";
        import * as aws from "@pulumi/aws";

        const ec2 = new aws.ec2.VpcEndpoint("ec2", {
            vpcId: main.id,
            serviceName: "com.amazonaws.us-west-2.ec2",
            vpcEndpointType: "Interface",
            securityGroupIds: [sg1.id],
            privateDnsEnabled: true,
        });
        ```
        ```python
        import pulumi
        import pulumi_aws as aws

        ec2 = aws.ec2.VpcEndpoint("ec2",
            vpc_id=main["id"],
            service_name="com.amazonaws.us-west-2.ec2",
            vpc_endpoint_type="Interface",
            security_group_ids=[sg1["id"]],
            private_dns_enabled=True)
        ```
        ```csharp
        using System.Collections.Generic;
        using System.Linq;
        using Pulumi;
        using Aws = Pulumi.Aws;

        return await Deployment.RunAsync(() => 
        {
            var ec2 = new Aws.Ec2.VpcEndpoint("ec2", new()
            {
                VpcId = main.Id,
                ServiceName = "com.amazonaws.us-west-2.ec2",
                VpcEndpointType = "Interface",
                SecurityGroupIds = new[]
                {
                    sg1.Id,
                },
                PrivateDnsEnabled = true,
            });

        });
        ```
        ```go
        package main

        import (
        	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
        	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
        )

        func main() {
        	pulumi.Run(func(ctx *pulumi.Context) error {
        		_, err := ec2.NewVpcEndpoint(ctx, "ec2", &ec2.VpcEndpointArgs{
        			VpcId:           pulumi.Any(main.Id),
        			ServiceName:     pulumi.String("com.amazonaws.us-west-2.ec2"),
        			VpcEndpointType: pulumi.String("Interface"),
        			SecurityGroupIds: pulumi.StringArray{
        				sg1.Id,
        			},
        			PrivateDnsEnabled: pulumi.Bool(true),
        		})
        		if err != nil {
        			return err
        		}
        		return nil
        	})
        }
        ```
        ```java
        package generated_program;

        import com.pulumi.Context;
        import com.pulumi.Pulumi;
        import com.pulumi.core.Output;
        import com.pulumi.aws.ec2.VpcEndpoint;
        import com.pulumi.aws.ec2.VpcEndpointArgs;
        import java.util.List;
        import java.util.ArrayList;
        import java.util.Map;
        import java.io.File;
        import java.nio.file.Files;
        import java.nio.file.Paths;

        public class App {
            public static void main(String[] args) {
                Pulumi.run(App::stack);
            }

            public static void stack(Context ctx) {
                var ec2 = new VpcEndpoint("ec2", VpcEndpointArgs.builder()        
                    .vpcId(main.id())
                    .serviceName("com.amazonaws.us-west-2.ec2")
                    .vpcEndpointType("Interface")
                    .securityGroupIds(sg1.id())
                    .privateDnsEnabled(true)
                    .build());

            }
        }
        ```
        ```yaml
        resources:
          ec2:
            type: aws:ec2:VpcEndpoint
            properties:
              vpcId: ${main.id}
              serviceName: com.amazonaws.us-west-2.ec2
              vpcEndpointType: Interface
              securityGroupIds:
                - ${sg1.id}
              privateDnsEnabled: true
        ```
        <!--End PulumiCodeChooser -->

        ### Gateway Load Balancer Endpoint Type

        <!--Start PulumiCodeChooser -->
        ```typescript
        import * as pulumi from "@pulumi/pulumi";
        import * as aws from "@pulumi/aws";

        const current = aws.getCallerIdentity({});
        const example = new aws.ec2.VpcEndpointService("example", {
            acceptanceRequired: false,
            allowedPrincipals: [current.then(current => current.arn)],
            gatewayLoadBalancerArns: [exampleAwsLb.arn],
        });
        const exampleVpcEndpoint = new aws.ec2.VpcEndpoint("example", {
            serviceName: example.serviceName,
            subnetIds: [exampleAwsSubnet.id],
            vpcEndpointType: example.serviceType,
            vpcId: exampleAwsVpc.id,
        });
        ```
        ```python
        import pulumi
        import pulumi_aws as aws

        current = aws.get_caller_identity()
        example = aws.ec2.VpcEndpointService("example",
            acceptance_required=False,
            allowed_principals=[current.arn],
            gateway_load_balancer_arns=[example_aws_lb["arn"]])
        example_vpc_endpoint = aws.ec2.VpcEndpoint("example",
            service_name=example.service_name,
            subnet_ids=[example_aws_subnet["id"]],
            vpc_endpoint_type=example.service_type,
            vpc_id=example_aws_vpc["id"])
        ```
        ```csharp
        using System.Collections.Generic;
        using System.Linq;
        using Pulumi;
        using Aws = Pulumi.Aws;

        return await Deployment.RunAsync(() => 
        {
            var current = Aws.GetCallerIdentity.Invoke();

            var example = new Aws.Ec2.VpcEndpointService("example", new()
            {
                AcceptanceRequired = false,
                AllowedPrincipals = new[]
                {
                    current.Apply(getCallerIdentityResult => getCallerIdentityResult.Arn),
                },
                GatewayLoadBalancerArns = new[]
                {
                    exampleAwsLb.Arn,
                },
            });

            var exampleVpcEndpoint = new Aws.Ec2.VpcEndpoint("example", new()
            {
                ServiceName = example.ServiceName,
                SubnetIds = new[]
                {
                    exampleAwsSubnet.Id,
                },
                VpcEndpointType = example.ServiceType,
                VpcId = exampleAwsVpc.Id,
            });

        });
        ```
        ```go
        package main

        import (
        	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws"
        	"github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
        	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
        )

        func main() {
        	pulumi.Run(func(ctx *pulumi.Context) error {
        		current, err := aws.GetCallerIdentity(ctx, nil, nil)
        		if err != nil {
        			return err
        		}
        		example, err := ec2.NewVpcEndpointService(ctx, "example", &ec2.VpcEndpointServiceArgs{
        			AcceptanceRequired: pulumi.Bool(false),
        			AllowedPrincipals: pulumi.StringArray{
        				pulumi.String(current.Arn),
        			},
        			GatewayLoadBalancerArns: pulumi.StringArray{
        				exampleAwsLb.Arn,
        			},
        		})
        		if err != nil {
        			return err
        		}
        		_, err = ec2.NewVpcEndpoint(ctx, "example", &ec2.VpcEndpointArgs{
        			ServiceName: example.ServiceName,
        			SubnetIds: pulumi.StringArray{
        				exampleAwsSubnet.Id,
        			},
        			VpcEndpointType: example.ServiceType,
        			VpcId:           pulumi.Any(exampleAwsVpc.Id),
        		})
        		if err != nil {
        			return err
        		}
        		return nil
        	})
        }
        ```
        ```java
        package generated_program;

        import com.pulumi.Context;
        import com.pulumi.Pulumi;
        import com.pulumi.core.Output;
        import com.pulumi.aws.AwsFunctions;
        import com.pulumi.aws.inputs.GetCallerIdentityArgs;
        import com.pulumi.aws.ec2.VpcEndpointService;
        import com.pulumi.aws.ec2.VpcEndpointServiceArgs;
        import com.pulumi.aws.ec2.VpcEndpoint;
        import com.pulumi.aws.ec2.VpcEndpointArgs;
        import java.util.List;
        import java.util.ArrayList;
        import java.util.Map;
        import java.io.File;
        import java.nio.file.Files;
        import java.nio.file.Paths;

        public class App {
            public static void main(String[] args) {
                Pulumi.run(App::stack);
            }

            public static void stack(Context ctx) {
                final var current = AwsFunctions.getCallerIdentity();

                var example = new VpcEndpointService("example", VpcEndpointServiceArgs.builder()        
                    .acceptanceRequired(false)
                    .allowedPrincipals(current.applyValue(getCallerIdentityResult -> getCallerIdentityResult.arn()))
                    .gatewayLoadBalancerArns(exampleAwsLb.arn())
                    .build());

                var exampleVpcEndpoint = new VpcEndpoint("exampleVpcEndpoint", VpcEndpointArgs.builder()        
                    .serviceName(example.serviceName())
                    .subnetIds(exampleAwsSubnet.id())
                    .vpcEndpointType(example.serviceType())
                    .vpcId(exampleAwsVpc.id())
                    .build());

            }
        }
        ```
        ```yaml
        resources:
          example:
            type: aws:ec2:VpcEndpointService
            properties:
              acceptanceRequired: false
              allowedPrincipals:
                - ${current.arn}
              gatewayLoadBalancerArns:
                - ${exampleAwsLb.arn}
          exampleVpcEndpoint:
            type: aws:ec2:VpcEndpoint
            name: example
            properties:
              serviceName: ${example.serviceName}
              subnetIds:
                - ${exampleAwsSubnet.id}
              vpcEndpointType: ${example.serviceType}
              vpcId: ${exampleAwsVpc.id}
        variables:
          current:
            fn::invoke:
              Function: aws:getCallerIdentity
              Arguments: {}
        ```
        <!--End PulumiCodeChooser -->

        ## Import

        Using `pulumi import`, import VPC Endpoints using the VPC endpoint `id`. For example:

        ```sh
        $ pulumi import aws:ec2/vpcEndpoint:VpcEndpoint endpoint1 vpce-3ecf2a57
        ```

        :param str service_name: The service name. For AWS services the service name is usually in the form `com.amazonaws.<region>.<service>` (the SageMaker Notebook service is an exception to this rule, the service name is in the form `aws.sagemaker.<region>.notebook`).
        :param bool auto_accept: Accept the VPC endpoint (the VPC endpoint and service need to be in the same AWS account).
        :param pulumi.Input['pulumi_aws.ec2.VpcEndpointDnsOptionsArgs'] dns_options: The DNS options for the endpoint. See dns_options below.
        :param pulumi.Input[str] ip_address_type: The IP address type for the endpoint. Valid values are `ipv4`, `dualstack`, and `ipv6`.
        :param pulumi.Input[str] policy: A policy to attach to the endpoint that controls access to the service. This is a JSON formatted string. Defaults to full access. All `Gateway` and some `Interface` endpoints support policies - see the [relevant AWS documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html) for more details.
        :param bool private_dns_enabled: Whether or not to associate a private hosted zone with the specified VPC. Applicable for endpoints of type Interface. Defaults to `false`.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] route_table_ids: One or more route table IDs. Applicable for endpoints of type `Gateway`.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] security_group_ids: The ID of one or more security groups to associate with the network interface. Applicable for endpoints of type `Interface`.
               If no security groups are specified, the VPC's [default security group](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup) is associated with the endpoint.
        :param pulumi.Input[Sequence[pulumi.Input[str]]] subnet_ids: The ID of one or more subnets in which to create a network interface for the endpoint. Applicable for endpoints of type `GatewayLoadBalancer` and `Interface`. Interface type endpoints cannot function without being assigned to a subnet.
        :param pulumi.Input[Mapping[str, pulumi.Input[str]]] tags: A map of tags to assign to the resource. If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
        :param pulumi.Input[str] vpc_endpoint_type: The VPC endpoint type, `Gateway`, `GatewayLoadBalancer`, or `Interface`. Defaults to `Gateway`.
        """
        pulumi.set(__self__, "service_name", service_name)
        if auto_accept is not None:
            pulumi.set(__self__, "auto_accept", auto_accept)
        if dns_options is not None:
            pulumi.set(__self__, "dns_options", dns_options)
        if ip_address_type is not None:
            pulumi.set(__self__, "ip_address_type", ip_address_type)
        if policy is not None:
            pulumi.set(__self__, "policy", policy)
        if private_dns_enabled is not None:
            pulumi.set(__self__, "private_dns_enabled", private_dns_enabled)
        if route_table_ids is not None:
            pulumi.set(__self__, "route_table_ids", route_table_ids)
        if security_group_ids is not None:
            pulumi.set(__self__, "security_group_ids", security_group_ids)
        if subnet_ids is not None:
            pulumi.set(__self__, "subnet_ids", subnet_ids)
        if tags is not None:
            pulumi.set(__self__, "tags", tags)
        if vpc_endpoint_type is not None:
            pulumi.set(__self__, "vpc_endpoint_type", vpc_endpoint_type)

    @property
    @pulumi.getter(name="serviceName")
    def service_name(self) -> str:
        """
        The service name. For AWS services the service name is usually in the form `com.amazonaws.<region>.<service>` (the SageMaker Notebook service is an exception to this rule, the service name is in the form `aws.sagemaker.<region>.notebook`).
        """
        return pulumi.get(self, "service_name")

    @service_name.setter
    def service_name(self, value: str):
        pulumi.set(self, "service_name", value)

    @property
    @pulumi.getter(name="autoAccept")
    def auto_accept(self) -> Optional[bool]:
        """
        Accept the VPC endpoint (the VPC endpoint and service need to be in the same AWS account).
        """
        return pulumi.get(self, "auto_accept")

    @auto_accept.setter
    def auto_accept(self, value: Optional[bool]):
        pulumi.set(self, "auto_accept", value)

    @property
    @pulumi.getter(name="dnsOptions")
    def dns_options(self) -> Optional[pulumi.Input['pulumi_aws.ec2.VpcEndpointDnsOptionsArgs']]:
        """
        The DNS options for the endpoint. See dns_options below.
        """
        return pulumi.get(self, "dns_options")

    @dns_options.setter
    def dns_options(self, value: Optional[pulumi.Input['pulumi_aws.ec2.VpcEndpointDnsOptionsArgs']]):
        pulumi.set(self, "dns_options", value)

    @property
    @pulumi.getter(name="ipAddressType")
    def ip_address_type(self) -> Optional[pulumi.Input[str]]:
        """
        The IP address type for the endpoint. Valid values are `ipv4`, `dualstack`, and `ipv6`.
        """
        return pulumi.get(self, "ip_address_type")

    @ip_address_type.setter
    def ip_address_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "ip_address_type", value)

    @property
    @pulumi.getter
    def policy(self) -> Optional[pulumi.Input[str]]:
        """
        A policy to attach to the endpoint that controls access to the service. This is a JSON formatted string. Defaults to full access. All `Gateway` and some `Interface` endpoints support policies - see the [relevant AWS documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html) for more details.
        """
        return pulumi.get(self, "policy")

    @policy.setter
    def policy(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "policy", value)

    @property
    @pulumi.getter(name="privateDnsEnabled")
    def private_dns_enabled(self) -> Optional[bool]:
        """
        Whether or not to associate a private hosted zone with the specified VPC. Applicable for endpoints of type Interface. Defaults to `false`.
        """
        return pulumi.get(self, "private_dns_enabled")

    @private_dns_enabled.setter
    def private_dns_enabled(self, value: Optional[bool]):
        pulumi.set(self, "private_dns_enabled", value)

    @property
    @pulumi.getter(name="routeTableIds")
    def route_table_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        One or more route table IDs. Applicable for endpoints of type `Gateway`.
        """
        return pulumi.get(self, "route_table_ids")

    @route_table_ids.setter
    def route_table_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "route_table_ids", value)

    @property
    @pulumi.getter(name="securityGroupIds")
    def security_group_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        The ID of one or more security groups to associate with the network interface. Applicable for endpoints of type `Interface`.
        If no security groups are specified, the VPC's [default security group](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup) is associated with the endpoint.
        """
        return pulumi.get(self, "security_group_ids")

    @security_group_ids.setter
    def security_group_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "security_group_ids", value)

    @property
    @pulumi.getter(name="subnetIds")
    def subnet_ids(self) -> Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]:
        """
        The ID of one or more subnets in which to create a network interface for the endpoint. Applicable for endpoints of type `GatewayLoadBalancer` and `Interface`. Interface type endpoints cannot function without being assigned to a subnet.
        """
        return pulumi.get(self, "subnet_ids")

    @subnet_ids.setter
    def subnet_ids(self, value: Optional[pulumi.Input[Sequence[pulumi.Input[str]]]]):
        pulumi.set(self, "subnet_ids", value)

    @property
    @pulumi.getter
    def tags(self) -> Optional[pulumi.Input[Mapping[str, pulumi.Input[str]]]]:
        """
        A map of tags to assign to the resource. If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
        """
        return pulumi.get(self, "tags")

    @tags.setter
    def tags(self, value: Optional[pulumi.Input[Mapping[str, pulumi.Input[str]]]]):
        pulumi.set(self, "tags", value)

    @property
    @pulumi.getter(name="vpcEndpointType")
    def vpc_endpoint_type(self) -> Optional[pulumi.Input[str]]:
        """
        The VPC endpoint type, `Gateway`, `GatewayLoadBalancer`, or `Interface`. Defaults to `Gateway`.
        """
        return pulumi.get(self, "vpc_endpoint_type")

    @vpc_endpoint_type.setter
    def vpc_endpoint_type(self, value: Optional[pulumi.Input[str]]):
        pulumi.set(self, "vpc_endpoint_type", value)


