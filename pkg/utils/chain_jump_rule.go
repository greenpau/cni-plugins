package utils

import (
	"fmt"
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
	chainProps, err := getChainProps(v, tableName, srcChainName)
	if err != nil {
		return nil, err
	}
	if chainProps.RuleCount == 0 {
		return nil, nil
	}

	for _, r := range chainProps.Rules {
		if len(r.Exprs) != 1 {
			continue
		}
		rr, err := r.Exprs[0].(*expr.Verdict)
		if err == false {
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

	return nil, nil
}

// CreateJumpRule create a jump rule from one chain to another.
func CreateJumpRule(v, tableName, srcChainName, dstChainName string) error {
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

	chainProps, err := getChainProps(v, tableName, srcChainName)
	if err != nil {
		return fmt.Errorf(
			"failed adding jump rule from chain %s in ipv%s %s table to chain %s due to failure to list chains: %s",
			srcChainName, v, tableName, dstChainName, err,
		)
	}

	r := &nftables.Rule{
		Table: tb,
		Chain: ch,
		Exprs: []expr.Any{},
	}

	if chainProps.RuleCount > 0 {
		r.Position = chainProps.Positions[0]
	}

	r.Exprs = append(r.Exprs, &expr.Verdict{
		Kind:  expr.VerdictJump,
		Chain: dstChainName,
	})

	if chainProps.RuleCount == 0 {
		conn.AddRule(r)
	} else {
		conn.InsertRule(r)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding jump rule from chain %s in ipv%s table to chain %s: %s",
			srcChainName, v, tableName, dstChainName, err,
		)
	}

	return nil
}
