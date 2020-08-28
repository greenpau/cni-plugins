package utils

import (
	"fmt"
	"github.com/google/nftables"
)

var defaultDropPolicy = nftables.ChainPolicyDrop

// IsChainExists checks whether a chain exists.
func IsChainExists(v, tableName, chainName string) (bool, error) {
	if err := isSupportedIPVersion(v); err != nil {
		return false, err
	}

	conn, err := initNftConn()
	if err != nil {
		return false, err
	}

	chains, err := conn.ListChains()
	if err != nil {
		return false, err
	}

	for _, chain := range chains {
		if chain == nil {
			continue
		}
		if chain.Name != chainName {
			continue
		}
		if chain.Table.Name != tableName {
			continue
		}
		if v == "4" {
			if chain.Table.Family != nftables.TableFamilyIPv4 {
				continue
			}
		} else {
			if chain.Table.Family != nftables.TableFamilyIPv6 {
				continue
			}
		}
		return true, nil
	}
	return false, nil
}

// CreateNatPostRoutingChain creates a postrouting chain in nat table.
//
// NF_INET_POST_ROUTING: this hook in the ipfinishoutput() function
// before they leave the computer.
func CreateNatPostRoutingChain(v, tableName, chainName string) error {
	return CreateChain(v, tableName, chainName, "nat", "postrouting", "snat")
}

// CreateNatPreRoutingChain creates a prerouting chain in nat table.
//
// NF_INET_PRE_ROUTING: incoming packets pass this hook in the ip_rcv()
// (linux/net/ipv4/ip_input.c) function before they are processed
// by the routing code.
func CreateNatPreRoutingChain(v, tableName, chainName string) error {
	return CreateChain(v, tableName, chainName, "nat", "prerouting", "dnat")
}

// CreateNatOutputChain creates an output chain in nat table.
//
// NF_INET_LOCAL_OUT: all outgoing packets created in the local
// computer pass this hook in the function ip_build_and_send_pkt().
func CreateNatOutputChain(v, tableName, chainName string) error {
	return CreateChain(v, tableName, chainName, "nat", "output", "dnat")
}

// CreateNatInputChain creates an input chain in nat table.
//
// NF_INET_LOCAL_IN: all incoming packets addressed to the local
// computer pass this hook in the function ip_local_deliver().
func CreateNatInputChain(v, tableName, chainName string) error {
	return CreateChain(v, tableName, chainName, "nat", "input", "snat")
}

// CreateRawPreRoutingChain creates a prerouting chain in raw table.
func CreateRawPreRoutingChain(v, tableName, chainName string) error {
	return CreateChain(v, tableName, chainName, "filter", "prerouting", "raw")
}

// CreateChain creates NAT chain of a specific type.
func CreateChain(v, tableName, chainName, chainType, chainHookType, chainPriority string) error {
	if err := isSupportedIPVersion(v); err != nil {
		return err
	}

	conn, err := initNftConn()
	if err != nil {
		return err
	}

	tb := &nftables.Table{
		Name: tableName,
	}

	if v == "4" {
		tb.Family = nftables.TableFamilyIPv4
	} else {
		tb.Family = nftables.TableFamilyIPv6
	}
	ch := &nftables.Chain{
		Name:  chainName,
		Table: tb,
	}

	switch chainType {
	case "nat":
		ch.Type = nftables.ChainTypeNAT
	case "filter":
		ch.Type = nftables.ChainTypeFilter
	case "route":
		ch.Type = nftables.ChainTypeRoute
	default:
		if chainType != "none" {
			return fmt.Errorf("unsupported table type: %s", chainType)
		}
	}

	switch chainHookType {
	case "input":
		ch.Hooknum = nftables.ChainHookInput
	case "forward":
		ch.Hooknum = nftables.ChainHookForward
	case "output":
		ch.Hooknum = nftables.ChainHookOutput
	case "prerouting":
		ch.Hooknum = nftables.ChainHookPrerouting
	case "postrouting":
		ch.Hooknum = nftables.ChainHookPostrouting
	default:
		if chainHookType != "none" {
			return fmt.Errorf("unsupported chain type: %s", chainHookType)
		}
	}

	switch chainPriority {
	case "dnat":
		ch.Priority = nftables.ChainPriorityNATDest
	case "snat":
		ch.Priority = nftables.ChainPriorityNATSource
	case "raw":
		ch.Priority = nftables.ChainPriorityRaw
	case "none":
		// do nothing
	default:
		if chainPriority != "none" {
			return fmt.Errorf("unsupported chain priority: %s", chainPriority)
		}
	}

	conn.AddChain(ch)
	if err = conn.Flush(); err != nil {
		return err
	}
	return nil
}

// CreateFilterForwardChain creates forward chain in filter table.
func CreateFilterForwardChain(v, tableName, chainName string) error {
	if err := isSupportedIPVersion(v); err != nil {
		return err
	}

	conn, err := initNftConn()
	if err != nil {
		return err
	}

	tb := &nftables.Table{
		Name: tableName,
	}
	if v == "4" {
		tb.Family = nftables.TableFamilyIPv4
	} else {
		tb.Family = nftables.TableFamilyIPv6
	}
	ch := &nftables.Chain{
		Name:     chainName,
		Table:    tb,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &defaultDropPolicy,
	}
	conn.AddChain(ch)
	if err = conn.Flush(); err != nil {
		return err
	}

	if err := addLogDenyRule(v, tableName, chainName); err != nil {
		return err
	}

	return nil
}

// DeleteChain deletes a particular chain.
func DeleteChain(v, tableName, chainName string) error {
	if err := isSupportedIPVersion(v); err != nil {
		return err
	}

	conn, err := initNftConn()
	if err != nil {
		return err
	}

	tb := &nftables.Table{
		Name: tableName,
	}
	if v == "4" {
		tb.Family = nftables.TableFamilyIPv4
	} else {
		tb.Family = nftables.TableFamilyIPv6
	}

	ch := &nftables.Chain{
		Name:  chainName,
		Table: tb,
	}

	conn.FlushChain(ch)
	conn.DelChain(ch)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"error deleting %s chain in %s table: %s",
			chainName, tableName, err,
		)
	}

	return nil
}
