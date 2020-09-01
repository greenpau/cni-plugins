package utils

import (
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"net"
)

// AddDestinationNatRewriteRules destination rewrite rule for the traffic
// arriving on a specific port.
func AddDestinationNatRewriteRules(opts map[string]interface{}) error {
	v := opts["version"].(string)
	tableName := opts["table"].(string)
	chainName := opts["chain"].(string)
	bridgeIntfName := opts["bridge_interface"].(string)
	addr := opts["ip_address"].(net.IPNet)
	pm := opts["port_mapping"].(MappingEntry)

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

	// counter packets 0 bytes 0

	r.Exprs = append(r.Exprs, &expr.Counter{})

	// match all interface but the interface
	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyIIFNAME,
		Register: 1,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		//Op:       expr.CmpOpEq,
		Op:       expr.CmpOpNeq,
		Register: 1,
		Data:     EncodeInterfaceName(bridgeIntfName),
	})

	// tcp dport <RCV_PORT_NUM>

	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyL4PROTO,
		Register: 1,
	})

	switch pm.Protocol {
	case "tcp":
		r.Exprs = append(r.Exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_TCP},
		})
	case "udp":
		r.Exprs = append(r.Exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{unix.IPPROTO_UDP},
		})
	default:
		return fmt.Errorf("unsupported protocol: %s", pm.Protocol)
	}

	// [ payload load 2b @ transport header + 2 => reg 1 ]
	r.Exprs = append(r.Exprs, &expr.Payload{
		DestRegister: 1,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       2, // TODO
		Len:          2, // TODO
	})

	// [ cmp eq reg 1 0x0000e60f ]
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(uint16(pm.HostPort)),
	})

	if v == "4" {
		r.Exprs = append(r.Exprs, &expr.Immediate{
			Register: 1,
			Data:     addr.IP.To4(),
		})
	} else {
		r.Exprs = append(r.Exprs, &expr.Immediate{
			Register: 1,
			Data:     addr.IP.To16(),
		})
	}

	r.Exprs = append(r.Exprs, &expr.Immediate{
		Register: 2,
		Data:     binaryutil.BigEndian.PutUint16(uint16(pm.ContainerPort)),
	})

	// ip daddr set <IP_ADDRESS>

	if v == "4" {
		// [ immediate reg 1 0x6600580a ]
		r.Exprs = append(r.Exprs, &expr.Immediate{
			Register: 1,
			Data:     addr.IP.To4(),
		})

		// [ payload write reg 1 => 4b @ network header + 16 csum_type 1 csum_off 10 csum_flags 0x1 ]
		r.Exprs = append(r.Exprs, &expr.Payload{
			OperationType:  expr.PayloadWrite,
			SourceRegister: 1,
			Base:           expr.PayloadBaseNetworkHeader,
			Offset:         16,
			Len:            4,
			CsumType:       expr.CsumTypeInet,
			CsumOffset:     10,
			CsumFlags:      unix.NFT_PAYLOAD_L4CSUM_PSEUDOHDR,
		})
	} else {
		r.Exprs = append(r.Exprs, &expr.Immediate{
			Register: 1,
			Data:     addr.IP.To16(),
		})
		r.Exprs = append(r.Exprs, &expr.Payload{
			OperationType:  expr.PayloadWrite,
			SourceRegister: 1,
			Base:           expr.PayloadBaseNetworkHeader,
			Offset:         24,
			Len:            16,
			CsumType:       expr.CsumTypeInet,
			CsumOffset:     10,
			CsumFlags:      unix.NFT_PAYLOAD_L4CSUM_PSEUDOHDR,
		})
	}

	// tcp dport set <MAPPED_PORT_NUM>

	r.Exprs = append(r.Exprs, &expr.Immediate{
		Register: 1,
		Data:     binaryutil.BigEndian.PutUint16(uint16(pm.ContainerPort)),
	})

	// [ payload write reg 1 => 2b @ transport header + 2 csum_type 1 csum_off 16 csum_flags 0x0 ]
	r.Exprs = append(r.Exprs, &expr.Payload{
		OperationType:  expr.PayloadWrite,
		SourceRegister: 1,
		Base:           expr.PayloadBaseTransportHeader,
		Offset:         2,
		Len:            2,
		CsumType:       expr.CsumTypeInet,
		CsumOffset:     16,
		CsumFlags:      unix.NFT_PAYLOAD_CSUM_NONE,
	})

	// return

	// [ immediate reg 0 return ]
	r.Exprs = append(r.Exprs, &expr.Verdict{
		Kind: expr.VerdictReturn,
	})

	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		return err
	}
	return nil
}
