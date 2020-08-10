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
func CreateNatPostRoutingChain(v, tableName, chainName string) error {
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
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	}
	conn.AddChain(ch)
	if err = conn.Flush(); err != nil {
		return err
	}
	return nil
}

<<<<<<< HEAD
=======
// CreateNatPreRoutingChain creates a prerouting chain in nat table.
func CreateNatPreRoutingChain(v, tableName, chainName string) error {
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
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	}
	conn.AddChain(ch)
	if err = conn.Flush(); err != nil {
		return err
	}
	return nil
}

>>>>>>> portmap
// CreateChain creates a new chain in a table.
func CreateChain(v, tableName, chainName string) error {
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
