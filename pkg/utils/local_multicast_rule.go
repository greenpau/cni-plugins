package utils

import (
	"fmt"
	current "github.com/containernetworking/cni/pkg/types/040"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"net"
)

func addPostRoutingLocalMulticastRule(opts map[string]interface{}) error {
	v := opts["version"].(string)
	tableName := opts["table"].(string)
	chainName := opts["chain"].(string)
	bridgeIntfName := opts["bridge_interface"].(string)
	addr := opts["ip_address"].(*current.IPConfig)

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

	// First, add rule for the traffic originating from the interface
	// to local multicast addresses.
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

	if addr.Version == "6" {
		r.Exprs = append(r.Exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       8,
			// Offset: 24,
			Len: 16,
		})
		r.Exprs = append(r.Exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     addr.Address.IP.To16(),
		})
	} else {
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
	}

	// destination XXXX for IPv6
	if addr.Version == "6" {
		// payload load 4b @ network header + 16 => reg 1
		// cmp eq reg 1 0xc8c8a8c0
		r.Exprs = append(r.Exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			// Offset:       8,
			Offset: 24,
			Len:    16,
		})
		r.Exprs = append(r.Exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     addr.Address.IP.To16(),
		})
	} else {
		// match ip destination 224.0.0.0/24 for IPv4
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
		r.Exprs = append(r.Exprs, &expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           []byte{0xff, 0xff, 0xff, 0x00},
			Xor:            []byte{0x0, 0x0, 0x0, 0x0},
		})
		r.Exprs = append(r.Exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     net.ParseIP("224.0.0.0").To4(),
		})
	}

	r.Exprs = append(r.Exprs, &expr.Counter{})
	r.Exprs = append(r.Exprs, &expr.Verdict{
		Kind: expr.VerdictReturn,
	})

	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding multicast rule in chain %s of ipv%s %s table for %v: %s",
			chainName, v, tableName, addr, err,
		)
	}
	return nil
}
