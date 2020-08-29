package utils

import (
	"fmt"
	"github.com/google/nftables"
)

// ChainInfo holds the rules of a particular chain
type ChainInfo struct {
	RuleCount int
	Positions []uint64
	Handles   []uint64
	Rules     []*nftables.Rule
}

// GetChainProps returns the rules and other properties of
// a particular chain.
func GetChainProps(v, tableName, chainName string) (*ChainInfo, error) {
	if err := isSupportedIPVersion(v); err != nil {
		return nil, err
	}

	conn, err := initNftConn()
	if err != nil {
		return nil, err
	}

	chains, err := conn.ListChains()
	if err != nil {
		return nil, err
	}

	var chain *nftables.Chain

	for _, c := range chains {
		if v == "4" {
			if c.Table.Family != nftables.TableFamilyIPv4 {
				continue
			}
		} else {
			if c.Table.Family != nftables.TableFamilyIPv6 {
				continue
			}
		}
		if chainName != c.Name {
			continue
		}
		if tableName != c.Table.Name {
			continue
		}
		chain = c
		break
	}

	if chain == nil {
		return nil, fmt.Errorf("chain %s in table %s not found", chainName, tableName)
	}

	info := &ChainInfo{
		RuleCount: 0,
		Positions: []uint64{},
		Handles:   []uint64{},
		Rules:     []*nftables.Rule{},
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

	rules, err := conn.GetRule(tb, ch)
	if err != nil {
		return nil, err
	}

	for _, r := range rules {
		if chainName != r.Chain.Name {
			continue
		}
		if tableName != r.Table.Name {
			continue
		}
		info.RuleCount++
		info.Positions = append(info.Positions, r.Position)
		info.Handles = append(info.Handles, r.Handle)
		info.Rules = append(info.Rules, r)
	}

	return info, nil
}
