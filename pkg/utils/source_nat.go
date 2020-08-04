package utils

import (
	"fmt"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	//"net"
)

func addPostRoutingSourceNatRule(v, tableName, chainName string, addr *current.IPConfig, intfName string) error {
	if v != "4" {
		return nil
	}
	conn, err := initNftConn()
	if err != nil {
		return err
	}

	tb := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyIPv4,
	}

	ch := &nftables.Chain{
		Name:  chainName,
		Table: tb,
	}

	r := &nftables.Rule{
		Table: tb,
		Chain: ch,
		Exprs: []expr.Any{},
	}

	// payload load 4b @ network header + 12 => reg 1
	r.Exprs = append(r.Exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       12,
		Len:          4,
	})
	// cmp eq reg 1 0x0245a8c0
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     addr.Address.IP.To4(),
	})

	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyOIFNAME,
		Register: 1,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     EncodeInterfaceName(intfName),
	})

	r.Exprs = append(r.Exprs, &expr.Counter{})
	r.Exprs = append(r.Exprs, &expr.Masq{})

	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding source NAT rule in chain %s of ipv%s %s table for %v: %s",
			chainName, v, tableName, addr, err,
		)
	}
	return nil
}
