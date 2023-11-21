// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.awsx.ec2.inputs;

import com.pulumi.aws.ec2.inputs.VpcEndpointDnsOptionsArgs;
import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


/**
 * Provides a VPC Endpoint resource.
 * 
 * &gt; **NOTE on VPC Endpoints and VPC Endpoint Associations:** The provider provides both standalone VPC Endpoint Associations for
 * Route Tables - (an association between a VPC endpoint and a single `route_table_id`),
 * Security Groups - (an association between a VPC endpoint and a single `security_group_id`),
 * and Subnets - (an association between a VPC endpoint and a single `subnet_id`) and
 * a VPC Endpoint resource with `route_table_ids` and `subnet_ids` attributes.
 * Do not use the same resource ID in both a VPC Endpoint resource and a VPC Endpoint Association resource.
 * Doing so will cause a conflict of associations and will overwrite the association.
 * 
 * ## Example Usage
 * ### Basic
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.aws.ec2.VpcEndpoint;
 * import com.pulumi.aws.ec2.VpcEndpointArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var s3 = new VpcEndpoint(&#34;s3&#34;, VpcEndpointArgs.builder()        
 *             .vpcId(aws_vpc.main().id())
 *             .serviceName(&#34;com.amazonaws.us-west-2.s3&#34;)
 *             .build());
 * 
 *     }
 * }
 * ```
 * ### Basic w/ Tags
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.aws.ec2.VpcEndpoint;
 * import com.pulumi.aws.ec2.VpcEndpointArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var s3 = new VpcEndpoint(&#34;s3&#34;, VpcEndpointArgs.builder()        
 *             .vpcId(aws_vpc.main().id())
 *             .serviceName(&#34;com.amazonaws.us-west-2.s3&#34;)
 *             .tags(Map.of(&#34;Environment&#34;, &#34;test&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * ### Interface Endpoint Type
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.aws.ec2.VpcEndpoint;
 * import com.pulumi.aws.ec2.VpcEndpointArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var ec2 = new VpcEndpoint(&#34;ec2&#34;, VpcEndpointArgs.builder()        
 *             .vpcId(aws_vpc.main().id())
 *             .serviceName(&#34;com.amazonaws.us-west-2.ec2&#34;)
 *             .vpcEndpointType(&#34;Interface&#34;)
 *             .securityGroupIds(aws_security_group.sg1().id())
 *             .privateDnsEnabled(true)
 *             .build());
 * 
 *     }
 * }
 * ```
 * ### Gateway Load Balancer Endpoint Type
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.aws.AwsFunctions;
 * import com.pulumi.aws.inputs.GetCallerIdentityArgs;
 * import com.pulumi.aws.ec2.VpcEndpointService;
 * import com.pulumi.aws.ec2.VpcEndpointServiceArgs;
 * import com.pulumi.aws.ec2.VpcEndpoint;
 * import com.pulumi.aws.ec2.VpcEndpointArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         final var current = AwsFunctions.getCallerIdentity();
 * 
 *         var exampleVpcEndpointService = new VpcEndpointService(&#34;exampleVpcEndpointService&#34;, VpcEndpointServiceArgs.builder()        
 *             .acceptanceRequired(false)
 *             .allowedPrincipals(current.applyValue(getCallerIdentityResult -&gt; getCallerIdentityResult.arn()))
 *             .gatewayLoadBalancerArns(aws_lb.example().arn())
 *             .build());
 * 
 *         var exampleVpcEndpoint = new VpcEndpoint(&#34;exampleVpcEndpoint&#34;, VpcEndpointArgs.builder()        
 *             .serviceName(exampleVpcEndpointService.serviceName())
 *             .subnetIds(aws_subnet.example().id())
 *             .vpcEndpointType(exampleVpcEndpointService.serviceType())
 *             .vpcId(aws_vpc.example().id())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * Using `pulumi import`, import VPC Endpoints using the VPC endpoint `id`. For example:
 * 
 * ```sh
 *  $ pulumi import aws:ec2/vpcEndpoint:VpcEndpoint endpoint1 vpce-3ecf2a57
 * ```
 * 
 */
public final class VpcEndpointSpecArgs extends com.pulumi.resources.ResourceArgs {

    public static final VpcEndpointSpecArgs Empty = new VpcEndpointSpecArgs();

    /**
     * Accept the VPC endpoint (the VPC endpoint and service need to be in the same AWS account).
     * 
     */
    @Import(name="autoAccept")
    private @Nullable Boolean autoAccept;

    /**
     * @return Accept the VPC endpoint (the VPC endpoint and service need to be in the same AWS account).
     * 
     */
    public Optional<Boolean> autoAccept() {
        return Optional.ofNullable(this.autoAccept);
    }

    /**
     * The DNS options for the endpoint. See dns_options below.
     * 
     */
    @Import(name="dnsOptions")
    private @Nullable Output<VpcEndpointDnsOptionsArgs> dnsOptions;

    /**
     * @return The DNS options for the endpoint. See dns_options below.
     * 
     */
    public Optional<Output<VpcEndpointDnsOptionsArgs>> dnsOptions() {
        return Optional.ofNullable(this.dnsOptions);
    }

    /**
     * The IP address type for the endpoint. Valid values are `ipv4`, `dualstack`, and `ipv6`.
     * 
     */
    @Import(name="ipAddressType")
    private @Nullable Output<String> ipAddressType;

    /**
     * @return The IP address type for the endpoint. Valid values are `ipv4`, `dualstack`, and `ipv6`.
     * 
     */
    public Optional<Output<String>> ipAddressType() {
        return Optional.ofNullable(this.ipAddressType);
    }

    /**
     * A policy to attach to the endpoint that controls access to the service. This is a JSON formatted string. Defaults to full access. All `Gateway` and some `Interface` endpoints support policies - see the [relevant AWS documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html) for more details.
     * 
     */
    @Import(name="policy")
    private @Nullable Output<String> policy;

    /**
     * @return A policy to attach to the endpoint that controls access to the service. This is a JSON formatted string. Defaults to full access. All `Gateway` and some `Interface` endpoints support policies - see the [relevant AWS documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html) for more details.
     * 
     */
    public Optional<Output<String>> policy() {
        return Optional.ofNullable(this.policy);
    }

    /**
     * Whether or not to associate a private hosted zone with the specified VPC. Applicable for endpoints of type Interface. Defaults to `false`.
     * 
     */
    @Import(name="privateDnsEnabled")
    private @Nullable Boolean privateDnsEnabled;

    /**
     * @return Whether or not to associate a private hosted zone with the specified VPC. Applicable for endpoints of type Interface. Defaults to `false`.
     * 
     */
    public Optional<Boolean> privateDnsEnabled() {
        return Optional.ofNullable(this.privateDnsEnabled);
    }

    /**
     * One or more route table IDs. Applicable for endpoints of type `Gateway`.
     * 
     */
    @Import(name="routeTableIds")
    private @Nullable Output<List<String>> routeTableIds;

    /**
     * @return One or more route table IDs. Applicable for endpoints of type `Gateway`.
     * 
     */
    public Optional<Output<List<String>>> routeTableIds() {
        return Optional.ofNullable(this.routeTableIds);
    }

    /**
     * The ID of one or more security groups to associate with the network interface. Applicable for endpoints of type `Interface`.
     * If no security groups are specified, the VPC&#39;s [default security group](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup) is associated with the endpoint.
     * 
     */
    @Import(name="securityGroupIds")
    private @Nullable Output<List<String>> securityGroupIds;

    /**
     * @return The ID of one or more security groups to associate with the network interface. Applicable for endpoints of type `Interface`.
     * If no security groups are specified, the VPC&#39;s [default security group](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup) is associated with the endpoint.
     * 
     */
    public Optional<Output<List<String>>> securityGroupIds() {
        return Optional.ofNullable(this.securityGroupIds);
    }

    /**
     * The service name. For AWS services the service name is usually in the form `com.amazonaws.&lt;region&gt;.&lt;service&gt;` (the SageMaker Notebook service is an exception to this rule, the service name is in the form `aws.sagemaker.&lt;region&gt;.notebook`).
     * 
     */
    @Import(name="serviceName", required=true)
    private String serviceName;

    /**
     * @return The service name. For AWS services the service name is usually in the form `com.amazonaws.&lt;region&gt;.&lt;service&gt;` (the SageMaker Notebook service is an exception to this rule, the service name is in the form `aws.sagemaker.&lt;region&gt;.notebook`).
     * 
     */
    public String serviceName() {
        return this.serviceName;
    }

    /**
     * The ID of one or more subnets in which to create a network interface for the endpoint. Applicable for endpoints of type `GatewayLoadBalancer` and `Interface`. Interface type endpoints cannot function without being assigned to a subnet.
     * 
     */
    @Import(name="subnetIds")
    private @Nullable Output<List<String>> subnetIds;

    /**
     * @return The ID of one or more subnets in which to create a network interface for the endpoint. Applicable for endpoints of type `GatewayLoadBalancer` and `Interface`. Interface type endpoints cannot function without being assigned to a subnet.
     * 
     */
    public Optional<Output<List<String>>> subnetIds() {
        return Optional.ofNullable(this.subnetIds);
    }

    /**
     * A map of tags to assign to the resource. If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
     * 
     */
    @Import(name="tags")
    private @Nullable Output<Map<String,String>> tags;

    /**
     * @return A map of tags to assign to the resource. If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
     * 
     */
    public Optional<Output<Map<String,String>>> tags() {
        return Optional.ofNullable(this.tags);
    }

    /**
     * The VPC endpoint type, `Gateway`, `GatewayLoadBalancer`, or `Interface`. Defaults to `Gateway`.
     * 
     */
    @Import(name="vpcEndpointType")
    private @Nullable Output<String> vpcEndpointType;

    /**
     * @return The VPC endpoint type, `Gateway`, `GatewayLoadBalancer`, or `Interface`. Defaults to `Gateway`.
     * 
     */
    public Optional<Output<String>> vpcEndpointType() {
        return Optional.ofNullable(this.vpcEndpointType);
    }

    private VpcEndpointSpecArgs() {}

    private VpcEndpointSpecArgs(VpcEndpointSpecArgs $) {
        this.autoAccept = $.autoAccept;
        this.dnsOptions = $.dnsOptions;
        this.ipAddressType = $.ipAddressType;
        this.policy = $.policy;
        this.privateDnsEnabled = $.privateDnsEnabled;
        this.routeTableIds = $.routeTableIds;
        this.securityGroupIds = $.securityGroupIds;
        this.serviceName = $.serviceName;
        this.subnetIds = $.subnetIds;
        this.tags = $.tags;
        this.vpcEndpointType = $.vpcEndpointType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(VpcEndpointSpecArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private VpcEndpointSpecArgs $;

        public Builder() {
            $ = new VpcEndpointSpecArgs();
        }

        public Builder(VpcEndpointSpecArgs defaults) {
            $ = new VpcEndpointSpecArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autoAccept Accept the VPC endpoint (the VPC endpoint and service need to be in the same AWS account).
         * 
         * @return builder
         * 
         */
        public Builder autoAccept(@Nullable Boolean autoAccept) {
            $.autoAccept = autoAccept;
            return this;
        }

        /**
         * @param dnsOptions The DNS options for the endpoint. See dns_options below.
         * 
         * @return builder
         * 
         */
        public Builder dnsOptions(@Nullable Output<VpcEndpointDnsOptionsArgs> dnsOptions) {
            $.dnsOptions = dnsOptions;
            return this;
        }

        /**
         * @param dnsOptions The DNS options for the endpoint. See dns_options below.
         * 
         * @return builder
         * 
         */
        public Builder dnsOptions(VpcEndpointDnsOptionsArgs dnsOptions) {
            return dnsOptions(Output.of(dnsOptions));
        }

        /**
         * @param ipAddressType The IP address type for the endpoint. Valid values are `ipv4`, `dualstack`, and `ipv6`.
         * 
         * @return builder
         * 
         */
        public Builder ipAddressType(@Nullable Output<String> ipAddressType) {
            $.ipAddressType = ipAddressType;
            return this;
        }

        /**
         * @param ipAddressType The IP address type for the endpoint. Valid values are `ipv4`, `dualstack`, and `ipv6`.
         * 
         * @return builder
         * 
         */
        public Builder ipAddressType(String ipAddressType) {
            return ipAddressType(Output.of(ipAddressType));
        }

        /**
         * @param policy A policy to attach to the endpoint that controls access to the service. This is a JSON formatted string. Defaults to full access. All `Gateway` and some `Interface` endpoints support policies - see the [relevant AWS documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html) for more details.
         * 
         * @return builder
         * 
         */
        public Builder policy(@Nullable Output<String> policy) {
            $.policy = policy;
            return this;
        }

        /**
         * @param policy A policy to attach to the endpoint that controls access to the service. This is a JSON formatted string. Defaults to full access. All `Gateway` and some `Interface` endpoints support policies - see the [relevant AWS documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html) for more details.
         * 
         * @return builder
         * 
         */
        public Builder policy(String policy) {
            return policy(Output.of(policy));
        }

        /**
         * @param privateDnsEnabled Whether or not to associate a private hosted zone with the specified VPC. Applicable for endpoints of type Interface. Defaults to `false`.
         * 
         * @return builder
         * 
         */
        public Builder privateDnsEnabled(@Nullable Boolean privateDnsEnabled) {
            $.privateDnsEnabled = privateDnsEnabled;
            return this;
        }

        /**
         * @param routeTableIds One or more route table IDs. Applicable for endpoints of type `Gateway`.
         * 
         * @return builder
         * 
         */
        public Builder routeTableIds(@Nullable Output<List<String>> routeTableIds) {
            $.routeTableIds = routeTableIds;
            return this;
        }

        /**
         * @param routeTableIds One or more route table IDs. Applicable for endpoints of type `Gateway`.
         * 
         * @return builder
         * 
         */
        public Builder routeTableIds(List<String> routeTableIds) {
            return routeTableIds(Output.of(routeTableIds));
        }

        /**
         * @param routeTableIds One or more route table IDs. Applicable for endpoints of type `Gateway`.
         * 
         * @return builder
         * 
         */
        public Builder routeTableIds(String... routeTableIds) {
            return routeTableIds(List.of(routeTableIds));
        }

        /**
         * @param securityGroupIds The ID of one or more security groups to associate with the network interface. Applicable for endpoints of type `Interface`.
         * If no security groups are specified, the VPC&#39;s [default security group](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup) is associated with the endpoint.
         * 
         * @return builder
         * 
         */
        public Builder securityGroupIds(@Nullable Output<List<String>> securityGroupIds) {
            $.securityGroupIds = securityGroupIds;
            return this;
        }

        /**
         * @param securityGroupIds The ID of one or more security groups to associate with the network interface. Applicable for endpoints of type `Interface`.
         * If no security groups are specified, the VPC&#39;s [default security group](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup) is associated with the endpoint.
         * 
         * @return builder
         * 
         */
        public Builder securityGroupIds(List<String> securityGroupIds) {
            return securityGroupIds(Output.of(securityGroupIds));
        }

        /**
         * @param securityGroupIds The ID of one or more security groups to associate with the network interface. Applicable for endpoints of type `Interface`.
         * If no security groups are specified, the VPC&#39;s [default security group](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#DefaultSecurityGroup) is associated with the endpoint.
         * 
         * @return builder
         * 
         */
        public Builder securityGroupIds(String... securityGroupIds) {
            return securityGroupIds(List.of(securityGroupIds));
        }

        /**
         * @param serviceName The service name. For AWS services the service name is usually in the form `com.amazonaws.&lt;region&gt;.&lt;service&gt;` (the SageMaker Notebook service is an exception to this rule, the service name is in the form `aws.sagemaker.&lt;region&gt;.notebook`).
         * 
         * @return builder
         * 
         */
        public Builder serviceName(String serviceName) {
            $.serviceName = serviceName;
            return this;
        }

        /**
         * @param subnetIds The ID of one or more subnets in which to create a network interface for the endpoint. Applicable for endpoints of type `GatewayLoadBalancer` and `Interface`. Interface type endpoints cannot function without being assigned to a subnet.
         * 
         * @return builder
         * 
         */
        public Builder subnetIds(@Nullable Output<List<String>> subnetIds) {
            $.subnetIds = subnetIds;
            return this;
        }

        /**
         * @param subnetIds The ID of one or more subnets in which to create a network interface for the endpoint. Applicable for endpoints of type `GatewayLoadBalancer` and `Interface`. Interface type endpoints cannot function without being assigned to a subnet.
         * 
         * @return builder
         * 
         */
        public Builder subnetIds(List<String> subnetIds) {
            return subnetIds(Output.of(subnetIds));
        }

        /**
         * @param subnetIds The ID of one or more subnets in which to create a network interface for the endpoint. Applicable for endpoints of type `GatewayLoadBalancer` and `Interface`. Interface type endpoints cannot function without being assigned to a subnet.
         * 
         * @return builder
         * 
         */
        public Builder subnetIds(String... subnetIds) {
            return subnetIds(List.of(subnetIds));
        }

        /**
         * @param tags A map of tags to assign to the resource. If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
         * 
         * @return builder
         * 
         */
        public Builder tags(@Nullable Output<Map<String,String>> tags) {
            $.tags = tags;
            return this;
        }

        /**
         * @param tags A map of tags to assign to the resource. If configured with a provider `default_tags` configuration block present, tags with matching keys will overwrite those defined at the provider-level.
         * 
         * @return builder
         * 
         */
        public Builder tags(Map<String,String> tags) {
            return tags(Output.of(tags));
        }

        /**
         * @param vpcEndpointType The VPC endpoint type, `Gateway`, `GatewayLoadBalancer`, or `Interface`. Defaults to `Gateway`.
         * 
         * @return builder
         * 
         */
        public Builder vpcEndpointType(@Nullable Output<String> vpcEndpointType) {
            $.vpcEndpointType = vpcEndpointType;
            return this;
        }

        /**
         * @param vpcEndpointType The VPC endpoint type, `Gateway`, `GatewayLoadBalancer`, or `Interface`. Defaults to `Gateway`.
         * 
         * @return builder
         * 
         */
        public Builder vpcEndpointType(String vpcEndpointType) {
            return vpcEndpointType(Output.of(vpcEndpointType));
        }

        public VpcEndpointSpecArgs build() {
            $.serviceName = Objects.requireNonNull($.serviceName, "expected parameter 'serviceName' to be non-null");
            return $;
        }
    }

}
