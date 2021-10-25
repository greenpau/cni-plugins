package utils

import (
	"fmt"
	current "github.com/containernetworking/cni/pkg/types/040"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func addFilterForwardOutboundTrafficRule(v, tableName, chainName string, addr *current.IPConfig, intfName string) error {
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
		Data:     EncodeInterfaceName(intfName),
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

	r.Exprs = append(r.Exprs, &expr.Counter{})
	r.Exprs = append(r.Exprs, &expr.Verdict{
		Kind: expr.VerdictAccept,
	})

	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding outbound traffic filtering rule in chain %s of ipv%s %s table for %v: %s",
			chainName, v, tableName, addr, err,
		)
	}
	return nil
}
