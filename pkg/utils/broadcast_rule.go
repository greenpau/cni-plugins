package utils

import (
	"fmt"
	current "github.com/containernetworking/cni/pkg/types/040"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"net"
)

func addPostRoutingBroadcastRule(opts map[string]interface{}) error {
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

	// match ip destination 255.255.255.255
	//
	// payload load 4b @ network header + 16 => reg 1
	// bitwise reg 1 = (reg=1 & 0x00ffffff ) ^ 0x00000000
	// cmp eq reg 1 0x000000e0
	r.Exprs = append(r.Exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseNetworkHeader,
		Offset:       16,
		Len:          4,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     net.ParseIP("255.255.255.255").To4(),
	})

	r.Exprs = append(r.Exprs, &expr.Counter{})
	r.Exprs = append(r.Exprs, &expr.Verdict{
		Kind: expr.VerdictReturn,
	})

	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding broadcast rule in chain %s of ipv%s %s table for %v: %s",
			chainName, v, tableName, addr, err,
		)
	}
	return nil
}
