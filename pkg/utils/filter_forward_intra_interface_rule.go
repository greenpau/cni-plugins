package utils

import (
	"fmt"
	current "github.com/containernetworking/cni/pkg/types/040"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func addFilterForwardIntraInterfaceRule(v, tableName, chainName string, addr *current.IPConfig, intfName string) error {
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

	// nft add rule iifname "dummy0" oifname "dummy0" counter packets 0 bytes 0 accept
	r := &nftables.Rule{
		Table: tb,
		Chain: ch,
		Exprs: []expr.Any{},
	}

	// meta load iifname => reg 1
	// cmp eq reg 1 0x6d6d7564 0x00003079 0x00000000 0x00000000
	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyIIFNAME,
		Register: 1,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     EncodeInterfaceName(intfName),
	})

	// meta load oifname => reg 2
	// cmp eq reg 2 0x6d6d7564 0x00003079 0x00000000 0x00000000
	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyOIFNAME,
		Register: 1,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     EncodeInterfaceName(intfName),
	})

	// counter pkts 0 bytes 0
	r.Exprs = append(r.Exprs, &expr.Counter{})
	// immediate reg 0 accept
	r.Exprs = append(r.Exprs, &expr.Verdict{
		Kind: expr.VerdictAccept,
	})

	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding intra interface filtering rule in chain %s of ipv%s %s table for %v: %s",
			chainName, v, tableName, addr, err,
		)
	}
	return nil
}
