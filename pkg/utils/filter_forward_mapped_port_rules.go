package utils

import (
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/google/nftables/binaryutil"
	"golang.org/x/sys/unix"
	"net"
	"reflect"
)

// AddFilterForwardMappedPortRules adds a set of rules in forwarding chain of filter table.
func AddFilterForwardMappedPortRules(opts map[string]interface{}) error {
	v := opts["version"].(string)
	tableName := opts["table"].(string)
	chainName := opts["chain"].(string)
	bridgeIntfName := opts["bridge_interface"].(string)
	addr := opts["ip_address"].(net.IPNet)
	pm := opts["port_mapping"].(MappingEntry)

	if err := isSupportedIPVersion(v); err != nil {
		return err
	}

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

	r := &nftables.Rule{
		Table: tb,
		Chain: ch,
		Exprs: []expr.Any{},
	}

	if chain.RuleCount > 0 {
		r.Position = chain.Positions[0]
	}

	r.Exprs = append(r.Exprs, &expr.Meta{
		Key:      expr.MetaKeyOIFNAME,
		Register: 1,
	})
	r.Exprs = append(r.Exprs, &expr.Cmp{
		Op:       expr.CmpOpEq,
		Register: 1,
		Data:     EncodeInterfaceName(bridgeIntfName),
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
		r.Exprs = append(r.Exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       24,
			Len:          16,
		})
		r.Exprs = append(r.Exprs, &expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     addr.IP.To16(),
		})
	}

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
		Data:     binaryutil.BigEndian.PutUint16(uint16(pm.ContainerPort)),
	})

	r.Exprs = append(r.Exprs, &expr.Counter{})

	r.Exprs = append(r.Exprs, &expr.Verdict{
		Kind: expr.VerdictAccept,
	})

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

// RemoveFilterForwardMappedPortRules removes a set of rules in forwarding chain of filter table.
func RemoveFilterForwardMappedPortRules(opts map[string]interface{}) error {
	ruleHandles := []uint64{}
	v := opts["version"].(string)
	tableName := opts["table"].(string)
	chainName := opts["chain"].(string)
	bridgeIntfName := opts["bridge_interface"].(string)
	addr := opts["ip_address"].(net.IPNet)
	// pm := opts["port_mapping"].(MappingEntry)

	if err := isSupportedIPVersion(v); err != nil {
		return err
	}

	chain, err := GetChainProps(v, tableName, chainName)
	if err != nil {
		return err
	}

	for _, r := range chain.Rules {
		if len(r.Exprs) < 10 {
			continue
		}

		// check whether interface matches
		rr1, err := r.Exprs[0].(*expr.Meta)
		if err == false {
			continue
		}
		if rr1.SourceRegister != false || rr1.Register != 1 || rr1.Key != expr.MetaKeyOIFNAME {
			continue
		}

		rr2, err := r.Exprs[1].(*expr.Cmp)
		if err == false {
			continue
		}
		if rr2.Register != 1 || rr2.Op != 0 || !reflect.DeepEqual(EncodeInterfaceName(bridgeIntfName), rr2.Data) {
			continue
		}

		// check whether destination IP address matches
		rr3, err := r.Exprs[2].(*expr.Payload)
		if err == false {
			continue
		}
		if rr3.DestRegister != 1 || rr3.SourceRegister != 0 || rr3.Base != expr.PayloadBaseNetworkHeader {
			continue
		}

		if v == "4" {
			if rr3.Offset != 16 || rr3.Len != 4 {
				continue
			}
		} else {
			if rr3.Offset != 24 || rr3.Len != 16 {
				continue
			}
		}

		rr4, err := r.Exprs[3].(*expr.Cmp)
		if err == false {
			continue
		}
		if rr4.Register != 1 || rr4.Op != 0 {
			continue
		}

		if v == "4" && len(rr4.Data) != 4 {
			continue
		}
		if v == "6" && len(rr4.Data) != 16 {
			continue
		}
		if net.IP(rr4.Data).String() != addr.IP.String() {
			continue
		}

		ruleHandles = append(ruleHandles, r.Handle)
	}

	if len(ruleHandles) == 0 {
		return nil
	}

	// Delete rules
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

	for _, ruleHandle := range ruleHandles {
		conn.DelRule(&nftables.Rule{
			Table:  tb,
			Chain:  ch,
			Handle: ruleHandle,
		})
		if err := conn.Flush(); err != nil {
			return fmt.Errorf(
				"error deleting rule allowing traffic to mapped ports in chain %s of %s table: %s",
				chainName, tableName, err,
			)
		}

	}

	return nil

}
