// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"log/slog"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// AccountRole identifies the AWS account responsible for a category of EC2 operations.
type AccountRole string

const (
	// RoleNetworkOwner is the account that owns the VPC and pod subnets.
	// All ENI lifecycle operations (create, delete, assign/unassign IPs) execute here.
	RoleNetworkOwner AccountRole = "network-owner"

	// RoleInstanceOwner is the account that owns the EC2 instances.
	// All instance-level operations (attach, describe instances, instance types) execute here.
	RoleInstanceOwner AccountRole = "instance-owner"
)

// MultiAccountEC2Client splits EC2 API calls across multiple AWS accounts
// based on AccountRole. Each role maps to an EC2API client configured with
// credentials for the corresponding AWS account.
//
// After CreateNetworkInterface succeeds on the RoleNetworkOwner client, a
// CreateNetworkInterfacePermission call grants the RoleInstanceOwner account
// INSTANCE-ATTACH access so that AttachNetworkInterface can succeed.
type MultiAccountEC2Client struct {
	logger         *slog.Logger
	clients        map[AccountRole]EC2API
	localAccountID string
}

// NewMultiAccountEC2Client constructs a MultiAccountEC2Client.
// clients must contain entries for at least RoleNetworkOwner and RoleInstanceOwner.
// localAccountID is the AWS account ID of the instance-owner account, used when
// granting CreateNetworkInterfacePermission after cross-account ENI creation.
func NewMultiAccountEC2Client(logger *slog.Logger, clients map[AccountRole]EC2API, localAccountID string) *MultiAccountEC2Client {
	return &MultiAccountEC2Client{
		logger:         logger,
		clients:        clients,
		localAccountID: localAccountID,
	}
}

// client returns the EC2API for the given role.
func (c *MultiAccountEC2Client) client(role AccountRole) EC2API {
	return c.clients[role]
}

// *********************************************************************************
// --- VPC / Subnet / ENI-owner operations → RoleNetworkOwner ---
// *********************************************************************************

func (c *MultiAccountEC2Client) GetSubnets(ctx context.Context) (ipamTypes.SubnetMap, error) {
	return c.client(RoleNetworkOwner).GetSubnets(ctx)
}

func (c *MultiAccountEC2Client) GetVpcs(ctx context.Context) (ipamTypes.VirtualNetworkMap, error) {
	return c.client(RoleNetworkOwner).GetVpcs(ctx)
}

func (c *MultiAccountEC2Client) GetRouteTables(ctx context.Context) (ipamTypes.RouteTableMap, error) {
	return c.client(RoleNetworkOwner).GetRouteTables(ctx)
}

// Security groups must come from RoleNetworkOwner because CreateNetworkInterface
// executes there and cross-account SG references are rejected by AWS.
func (c *MultiAccountEC2Client) GetSecurityGroups(ctx context.Context) (types.SecurityGroupMap, error) {
	return c.client(RoleNetworkOwner).GetSecurityGroups(ctx)
}

func (c *MultiAccountEC2Client) GetDetachedNetworkInterfaces(ctx context.Context, tags ipamTypes.Tags, maxResults int32) ([]string, error) {
	return c.client(RoleNetworkOwner).GetDetachedNetworkInterfaces(ctx, tags, maxResults)
}

// CreateNetworkInterface creates the ENI in the RoleNetworkOwner account's subnet,
// then immediately grants the RoleInstanceOwner account INSTANCE-ATTACH permission
// so that AttachNetworkInterface can succeed.
func (c *MultiAccountEC2Client) CreateNetworkInterface(ctx context.Context, toAllocate int32, subnetID, desc string, groups []string, allocatePrefixes bool) (string, *eniTypes.ENI, error) {
	network := c.client(RoleNetworkOwner)
	eniID, eni, err := network.CreateNetworkInterface(ctx, toAllocate, subnetID, desc, groups, allocatePrefixes)
	if err != nil {
		return "", nil, err
	}

	if permErr := network.CreateNetworkInterfacePermission(ctx, eniID, c.localAccountID); permErr != nil {
		c.logger.Warn(
			"Failed to grant cross-account ENI attach permission. Deleting orphaned ENI",
			logfields.ENI, eniID,
			logfields.Error, permErr,
		)
		if delErr := network.DeleteNetworkInterface(ctx, eniID); delErr != nil {
			c.logger.Warn("Failed to delete orphaned ENI",
				logfields.ENI, eniID,
				logfields.Error, delErr,
			)
		}
		return "", nil, permErr
	}

	return eniID, eni, nil
}

func (c *MultiAccountEC2Client) CreateNetworkInterfacePermission(ctx context.Context, eniID string, accountID string) error {
	return c.client(RoleNetworkOwner).CreateNetworkInterfacePermission(ctx, eniID, accountID)
}

func (c *MultiAccountEC2Client) DeleteNetworkInterface(ctx context.Context, eniID string) error {
	return c.client(RoleNetworkOwner).DeleteNetworkInterface(ctx, eniID)
}

func (c *MultiAccountEC2Client) AssignPrivateIpAddresses(ctx context.Context, eniID string, addresses int32) ([]string, error) {
	return c.client(RoleNetworkOwner).AssignPrivateIpAddresses(ctx, eniID, addresses)
}

func (c *MultiAccountEC2Client) UnassignPrivateIpAddresses(ctx context.Context, eniID string, addresses []string) error {
	return c.client(RoleNetworkOwner).UnassignPrivateIpAddresses(ctx, eniID, addresses)
}

func (c *MultiAccountEC2Client) AssignENIPrefixes(ctx context.Context, eniID string, prefixes int32) error {
	return c.client(RoleNetworkOwner).AssignENIPrefixes(ctx, eniID, prefixes)
}

func (c *MultiAccountEC2Client) UnassignENIPrefixes(ctx context.Context, eniID string, prefixes []string) error {
	return c.client(RoleNetworkOwner).UnassignENIPrefixes(ctx, eniID, prefixes)
}

// *********************************************************************************
// --- Instance-owner operations → RoleInstanceOwner ---
// *********************************************************************************

func (c *MultiAccountEC2Client) GetInstance(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap, instanceID string) (*ipamTypes.Instance, error) {
	return c.client(RoleInstanceOwner).GetInstance(ctx, vpcs, subnets, instanceID)
}

func (c *MultiAccountEC2Client) GetInstances(ctx context.Context, vpcs ipamTypes.VirtualNetworkMap, subnets ipamTypes.SubnetMap) (*ipamTypes.InstanceMap, error) {
	return c.client(RoleInstanceOwner).GetInstances(ctx, vpcs, subnets)
}

func (c *MultiAccountEC2Client) GetInstanceTypes(ctx context.Context) ([]ec2_types.InstanceTypeInfo, error) {
	return c.client(RoleInstanceOwner).GetInstanceTypes(ctx)
}

func (c *MultiAccountEC2Client) AttachNetworkInterface(ctx context.Context, index int32, instanceID, eniID string) (string, error) {
	return c.client(RoleInstanceOwner).AttachNetworkInterface(ctx, index, instanceID, eniID)
}

func (c *MultiAccountEC2Client) ModifyNetworkInterface(ctx context.Context, eniID, attachmentID string, deleteOnTermination bool) error {
	return c.client(RoleInstanceOwner).ModifyNetworkInterface(ctx, eniID, attachmentID, deleteOnTermination)
}

func (c *MultiAccountEC2Client) AssociateEIP(ctx context.Context, eniID string, eipTags ipamTypes.Tags) (string, error) {
	return c.client(RoleInstanceOwner).AssociateEIP(ctx, eniID, eipTags)
}
