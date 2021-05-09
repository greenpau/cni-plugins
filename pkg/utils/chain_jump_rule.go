package utils

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// DeleteJumpRule deletes the chain jumping rule.
func DeleteJumpRule(v, tableName, srcChainName, dstChainName string) error {
	r, err := GetJumpRule(v, tableName, srcChainName, dstChainName)
	if err != nil {
		return err
	}
	if r == nil {
		return nil
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
		Name:  srcChainName,
		Table: tb,
	}

	conn.DelRule(&nftables.Rule{
		Table: tb,
		Chain: ch,
		//&nftables.Chain{Name: r.Chain.Name, Type: r.Chain.Type},
		Handle: r.Handle,
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"error deleting jump rule to %s chain found in chain %s in %s table: %s",
			dstChainName, r.Chain.Name, r.Table.Name, err,
		)
	}

	return nil
}

// GetJumpRule return information about a specific jump rule.
func GetJumpRule(v, tableName, srcChainName, dstChainName string) (*nftables.Rule, error) {
	if err := isSupportedIPVersion(v); err != nil {
		return nil, err
	}
	chainProps, err := GetChainProps(v, tableName, srcChainName)
	if err != nil {
		return nil, err
	}
	for _, r := range chainProps.Rules {
		for _, expression := range r.Exprs {
			rr, err := expression.(*expr.Verdict)

			if !err {
				continue
			}
			if rr.Kind != expr.VerdictJump {
				continue
			}
			if rr.Chain != dstChainName {
				continue
			}
			return r, nil
		}
	}

	return nil, nil
}

// CreateJumpRuleWithIPSourceMatch create a jump rule from one chain to another that will trigger when source address match ipAddress argument.
func CreateJumpRuleWithIPSourceMatch(v, tableName, srcChainName, dstChainName string, ipAddress net.IP) error {

	var conditions []expr.Any

	if v == "6" {
		// payload load 4b @ network header + 16 => reg 1
		// cmp eq reg 1 0xc8c8a8c0
		conditions = []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       24,
				Len:          16,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ipAddress.To16(),
			},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: dstChainName,
			},
		}
	} else {
		// payload load 4b @ network header + 16 => reg 1
		// cmp eq reg 1 0x6464a8c0 ]
		conditions = []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ipAddress.To4(),
			},
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: dstChainName,
			},
		}
	}
	return createJumpRule(v, tableName, srcChainName, dstChainName, conditions)
}

// CreateJumpRule create a jump rule from one chain to another.
func CreateJumpRule(v, tableName, srcChainName, dstChainName string) error {
	return createJumpRule(v, tableName, srcChainName, dstChainName, []expr.Any{
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: dstChainName,
		},
	})
}

func createJumpRule(v, tableName, srcChainName, dstChainName string, expressions []expr.Any) error {
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
		Name:  srcChainName,
		Table: tb,
	}

	chainProps, err := GetChainProps(v, tableName, srcChainName)
	if err != nil {
		return fmt.Errorf(
			"failed adding jump rule from chain %s in ipv%s %s table to chain %s due to failure to list chains: %s",
			srcChainName, v, tableName, dstChainName, err,
		)
	}

	r := &nftables.Rule{
		Table: tb,
		Chain: ch,
		Exprs: expressions,
	}

	if chainProps.RuleCount > 0 {
		r.Position = chainProps.Positions[0]
	}
	if chainProps.RuleCount == 0 {
		conn.AddRule(r)
	} else {
		conn.InsertRule(r)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding jump rule from chain %s in ipv%s table %s to chain %s: %s",
			srcChainName, v, tableName, dstChainName, err,
		)
	}

	return nil
}
