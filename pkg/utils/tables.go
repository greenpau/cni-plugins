package utils

import (
	"fmt"
	"github.com/google/nftables"
)

func isSupportedIPVersion(v string) error {
	if v != "4" && v != "6" {
		return fmt.Errorf("unsuppoted IP version %s", v)
	}
	return nil
}

// IsTableExist checks whether a table exists
func IsTableExist(v, tableName string) (bool, error) {
	if err := isSupportedIPVersion(v); err != nil {
		return false, err
	}
	conn, err := initNftConn()
	if err != nil {
		return false, err
	}

	tables, err := conn.ListTables()
	if err != nil {
		return false, err
	}

	for _, table := range tables {
		if table == nil {
			continue
		}
		if table.Name != tableName {
			continue
		}
		if v == "4" {
			if table.Family != nftables.TableFamilyIPv4 {
				continue
			}
		} else {
			if table.Family != nftables.TableFamilyIPv6 {
				continue
			}
		}
		return true, nil
	}

	return false, nil
}

// CreateTable creates a table.
func CreateTable(v, tableName string) error {
	if err := isSupportedIPVersion(v); err != nil {
		return err
	}
	conn, err := initNftConn()
	if err != nil {
		return err
	}

	t := &nftables.Table{
		Name: tableName,
	}
	if v == "4" {
		t.Family = nftables.TableFamilyIPv4
	} else {
		t.Family = nftables.TableFamilyIPv6
	}
	conn.AddTable(t)
	if err := conn.Flush(); err != nil {
		return err
	}
	return nil
}
