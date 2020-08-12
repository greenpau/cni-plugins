package utils

import (
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

func addLogDenyRule(v, tableName, chainName string) error {
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

	// log prefix "ipv6 input drop: " flags all
	prefix := fmt.Sprintf("ip%s forward drop: ", v)

	r := &nftables.Rule{
		Table: tb,
		Chain: ch,
		Exprs: []expr.Any{},
	}

	r.Exprs = append(r.Exprs, &expr.Log{
		Key:  unix.NFTA_LOG_PREFIX,
		Data: []byte(prefix),
	})

	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding default logging rule in chain %s of ipv%s %s table: %s",
			chainName, v, tableName, err,
		)
	}

	r = &nftables.Rule{
		Table: tb,
		Chain: ch,
		Exprs: []expr.Any{},
	}
	r.Exprs = append(r.Exprs, &expr.Counter{})
	r.Exprs = append(r.Exprs, &expr.Verdict{
		Kind: expr.VerdictDrop,
	})

	conn.AddRule(r)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf(
			"failed adding default deny with counter rule in chain %s of ipv%s %s table: %s",
			chainName, v, tableName, err,
		)
	}
	return nil
}
