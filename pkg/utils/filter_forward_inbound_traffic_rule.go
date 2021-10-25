package utils

import (
	"fmt"
	current "github.com/containernetworking/cni/pkg/types/040"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func addFilterForwardInboundTrafficRule(v, tableName, chainName string, addr *current.IPConfig, intfName string) error {
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

	// meta load oifname => reg 1
	// cmp eq reg 1 0x6d6d7564 0x00003079 0x00000000 0x00000000
	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyOIFNAME,
		Register: 1,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     EncodeInterfaceName(intfName),
	})

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
		// payload load 4b @ network header + 16 => reg 1
		// cmp eq reg 1 0x6464a8c0 ]
		r.Exprs = append(r.Exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		})
		r.Exprs = append(r.Exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     addr.Address.IP.To4(),
		})
	}

	// ct load state => reg 1 ]
	// bitwise reg 1 = (reg=1 & 0x00000006 ) ^ 0x00000000
	// cmp neq reg 1 0x00000000
	r.Exprs = append(r.Exprs, &expr.Ct{
		Register: 1,
		Key:      expr.CtKeySTATE,
	})
	r.Exprs = append(r.Exprs, &expr.Bitwise{
		SourceRegister: 1,
		DestRegister:   1,
		Xor:            []byte{0x0, 0x0, 0x0, 0x0},
		Mask:           []byte("\x06\x00\x00\x00"),
		Len:            4,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpNeq,
		Register: 1,
		Data:     []byte{0x0, 0x0, 0x0, 0x0},
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
			"failed adding inbound traffic filtering rule in chain %s of ipv%s %s table for %v: %s",
			chainName, v, tableName, addr, err,
		)
	}
	return nil
}
