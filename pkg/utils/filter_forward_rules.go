package utils

import (
	current "github.com/containernetworking/cni/pkg/types/040"
)

// AddFilterForwardRules adds a set of rules in forwarding chain of filter table.
func AddFilterForwardRules(v, tableName, chainName string, addr *current.IPConfig, intfName string) error {
	if err := isSupportedIPVersion(v); err != nil {
		return err
	}
	if err := addFilterForwardInboundTrafficRule(v, tableName, chainName, addr, intfName); err != nil {
		return err
	}
	if err := addFilterForwardOutboundTrafficRule(v, tableName, chainName, addr, intfName); err != nil {
		return err
	}
	if err := addFilterForwardIntraInterfaceRule(v, tableName, chainName, addr, intfName); err != nil {
		return err
	}
	return nil
}
