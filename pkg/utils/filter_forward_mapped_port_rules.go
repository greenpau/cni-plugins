package utils

import (
	"fmt"
	//"github.com/davecgh/go-spew/spew"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"net"
)

// AddFilterForwardMappedPortRules adds a set of rules in forwarding chain of filter table.
func AddFilterForwardMappedPortRules(v, tableName, chainName string, addr net.IPNet, intfName string, pm MappingEntry) error {
	if err := isSupportedIPVersion(v); err != nil {
		return err
	}

	//return fmt.Errorf("NFT-PORTMAP-ADD: %s", spew.Sdump(tableName))

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

	chain, err := GetChainProps(v, tableName, chainName)
	if err != nil {
		return err
	}
	//return fmt.Errorf("NFT-PORTMAP-ADD: %s", spew.Sdump(chain))

	r := &nftables.Rule{
		Table: tb,
		Chain: ch,
		Exprs: []expr.Any{},
	}

	if chain.RuleCount > 0 {
		r.Position = chain.Positions[0]
		r.Position = chain.Handles[0]
	}

	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyOIFNAME,
		Register: 1,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     EncodeInterfaceName(intfName),
	})

	if v == "4" {
		r.Exprs = append(r.Exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		})
		r.Exprs = append(r.Exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     addr.IP.To4(),
		})
	} else {
		return fmt.Errorf("IPv6 is unsupported")
	}

	r.Exprs = append(r.Exprs, &expr.Counter{})

	if chain.RuleCount == 0 {
		conn.AddRule(r)
	} else {
		conn.InsertRule(r)
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding filter forward mapped port rule to ipv%s chain %s in %s table: %s",
			v, chainName, tableName, err,
		)
	}

	return nil
}
