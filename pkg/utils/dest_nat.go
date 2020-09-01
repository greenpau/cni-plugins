package utils

import (
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"net"
)

// AddDestinationNatRules creates destination NAT rules
func AddDestinationNatRules(opts map[string]interface{}) error {
	v := opts["version"].(string)
	tableName := opts["table"].(string)
	chainName := opts["chain"].(string)
	bridgeIntfName := opts["bridge_interface"].(string)
	addr := opts["ip_address"].(net.IPNet)
	pm := opts["port_mapping"].(MappingEntry)

	/*
		rule := fmt.Sprintf(
			"%s dport { %d } dnat %s:%d;",
			pm.Protocol, pm.HostPort, addr.IP, pm.ContainerPort,
		)
		return fmt.Errorf("unsupported %s", rule)
	*/
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

	// match non-container interface
	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyIIFNAME,
		Register: 1,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpNeq,
		Register: 1,
		Data:     EncodeInterfaceName(bridgeIntfName),
	})

	// match port

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

	if v == "4" {
		r.Exprs = append(r.Exprs, &expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      unix.NFPROTO_IPV4,
			RegAddrMin:  1,
			RegProtoMin: 2,
		})
	} else {
		r.Exprs = append(r.Exprs, &expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      unix.NFPROTO_IPV6,
			RegAddrMin:  1,
			RegProtoMin: 2,
		})
	}

	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		return err
	}
	return nil
}
