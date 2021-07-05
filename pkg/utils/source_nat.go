package utils

import (
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// Add rules for masquarading traffic coming out of the conteiner. The
// resulting rule looks like
// iifname "<bridgeIntfName>" ip saddr <addr> counter masquerade
func addPostRoutingSourceNatRule(opts map[string]interface{}) error {
	v := opts["version"].(string)
	tableName := opts["table"].(string)
	chainName := opts["chain"].(string)
	bridgeIntfName := opts["bridge_interface"].(string)
	addr := opts["ip_address"].(*current.IPConfig)

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

	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyIIFNAME,
		Register: 1,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     EncodeInterfaceName(bridgeIntfName),
	})

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

// Add rules for masquarading traffic into the container. The resulting
// rule looks like
// oifname "<bridgeIntfName>" ip daddr <addr> counter masquerade
func AddPostRoutingDestNatRule(opts map[string]interface{}) error {
	v := opts["version"].(string)
	tableName := opts["table"].(string)
	chainName := opts["chain"].(string)
	bridgeIntfName := opts["bridge_interface"].(string)
	addr := opts["ip_address"].(net.IPNet)

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

	if v == "4" {
		conn.AddRule(
			&nftables.Rule{
				Table: tb,
				Chain: ch,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: EncodeInterfaceName(bridgeIntfName)},

					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr.IP.To4()},

					&expr.Counter{},
					&expr.Masq{},
				},
			},
		)
	} else {
		conn.AddRule(
			&nftables.Rule{
				Table: tb,
				Chain: ch,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: EncodeInterfaceName(bridgeIntfName)},

					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 4},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr.IP.To16()},

					&expr.Counter{},
					&expr.Masq{},
				},
			},
		)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding source NAT rule in chain %s of ipv%s %s table for %v: %s",
			chainName, v, tableName, addr, err,
		)
	}
	return nil
}
