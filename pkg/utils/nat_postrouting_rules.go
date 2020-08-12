package utils

import (
	"github.com/containernetworking/cni/pkg/types/current"
)

// AddPostRoutingRules adds a set of rules in postrouting chain of nat table.
func AddPostRoutingRules(v, tableName, chainName string, addr *current.IPConfig, intfName string) error {
	if err := isSupportedIPVersion(v); err != nil {
		return err
	}
	if err := addPostRoutingLocalMulticastRule(v, tableName, chainName, addr); err != nil {
		return err
	}
	if err := addPostRoutingBroadcastRule(v, tableName, chainName, addr); err != nil {
		return err
	}
	if err := addPostRoutingSourceNatRule(v, tableName, chainName, addr, intfName); err != nil {
		return err
	}
	return nil
}
