// Code generated by pulumi-gen-awsx DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package ec2

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-awsx/sdk/v2/go/awsx/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// [NOT YET IMPLEMENTED] Get the Default VPC for a region.
//
// Deprecated: Waiting for https://github.com/pulumi/pulumi/issues/7583. Use the DefaultVpc resource until resolved.
func GetDefaultVpc(ctx *pulumi.Context, args *GetDefaultVpcArgs, opts ...pulumi.InvokeOption) (*GetDefaultVpcResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDefaultVpcResult
	err := ctx.Invoke("awsx:ec2:getDefaultVpc", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// Arguments for getting the default VPC
type GetDefaultVpcArgs struct {
}

// Outputs from the default VPC configuration
type GetDefaultVpcResult struct {
	PrivateSubnetIds []string `pulumi:"privateSubnetIds"`
	PublicSubnetIds  []string `pulumi:"publicSubnetIds"`
	// The VPC ID for the default VPC
	VpcId string `pulumi:"vpcId"`
}

func GetDefaultVpcOutput(ctx *pulumi.Context, args GetDefaultVpcOutputArgs, opts ...pulumi.InvokeOption) GetDefaultVpcResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetDefaultVpcResult, error) {
			args := v.(GetDefaultVpcArgs)
			r, err := GetDefaultVpc(ctx, &args, opts...)
			var s GetDefaultVpcResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetDefaultVpcResultOutput)
}

// Arguments for getting the default VPC
type GetDefaultVpcOutputArgs struct {
}

func (GetDefaultVpcOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDefaultVpcArgs)(nil)).Elem()
}

// Outputs from the default VPC configuration
type GetDefaultVpcResultOutput struct{ *pulumi.OutputState }

func (GetDefaultVpcResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDefaultVpcResult)(nil)).Elem()
}

func (o GetDefaultVpcResultOutput) ToGetDefaultVpcResultOutput() GetDefaultVpcResultOutput {
	return o
}

func (o GetDefaultVpcResultOutput) ToGetDefaultVpcResultOutputWithContext(ctx context.Context) GetDefaultVpcResultOutput {
	return o
}

func (o GetDefaultVpcResultOutput) PrivateSubnetIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetDefaultVpcResult) []string { return v.PrivateSubnetIds }).(pulumi.StringArrayOutput)
}

func (o GetDefaultVpcResultOutput) PublicSubnetIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetDefaultVpcResult) []string { return v.PublicSubnetIds }).(pulumi.StringArrayOutput)
}

// The VPC ID for the default VPC
func (o GetDefaultVpcResultOutput) VpcId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDefaultVpcResult) string { return v.VpcId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDefaultVpcResultOutput{})
}
