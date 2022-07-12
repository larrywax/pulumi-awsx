// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.awsx.ec2.enums;

import com.pulumi.core.annotations.EnumType;
import java.lang.String;
import java.util.Objects;
import java.util.StringJoiner;

    /**
     * A type of subnet within a VPC.
     * 
     */
    @EnumType
    public enum SubnetType {
        /**
         * A subnet whose hosts can directly communicate with the internet.
         * 
         */
        Public("Public"),
        /**
         * A subnet whose hosts can not directly communicate with the internet, but can initiate outbound network traffic via a NAT Gateway.
         * 
         */
        Private("Private"),
        /**
         * A subnet whose hosts have no connectivity with the internet.
         * 
         */
        Isolated("Isolated");

        private final String value;

        SubnetType(String value) {
            this.value = Objects.requireNonNull(value);
        }

        @EnumType.Converter
        public String getValue() {
            return this.value;
        }

        @Override
        public String toString() {
            return new StringJoiner(", ", "SubnetType[", "]")
                .add("value='" + this.value + "'")
                .toString();
        }
    }
