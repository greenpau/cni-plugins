package utils

import (
	"github.com/containernetworking/cni/pkg/types/current"
)

// AddFilterForwardMappedRules adds a set of rules in forwarding chain of filter table.
func AddFilterForwardMappedRules(v, tableName, chainName string, addr *current.IPConfig, intfName string) error {
	if err := isSupportedIPVersion(v); err != nil {
		return err
	}
	if err := addFilterForwardMappedPortRule(v, tableName, chainName, addr, intfName); err != nil {
		return err
	}
	return nil
}
