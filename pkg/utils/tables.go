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

// IsFilterTableExist checks whether filter table exists.
func IsFilterTableExist(v, tableName string) (bool, error) {
	table, err := isTableExist(v, tableName)
	if err != nil {
		return false, err
	}
	if table != nil {
		return true, nil
	}
	return false, nil
}

// IsNatTableExist checks whether nat table exists.
func IsNatTableExist(v, tableName string) (bool, error) {
	table, err := isTableExist(v, tableName)
	if err != nil {
		return false, err
	}
	if table != nil {
		return true, nil
	}
	return false, nil
}

func isTableExist(v, tableName string) (*nftables.Table, error) {
	if err := isSupportedIPVersion(v); err != nil {
		return nil, err
	}
	conn, err := initNftConn()
	if err != nil {
		return nil, err
	}

	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
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
		return table, nil
	}

	return nil, nil
}

// CreateFilterTable creates filter table.
func CreateFilterTable(v, tableName string) error {
	return createTable(v, tableName)
}

// CreateNatTable creates nat table.
func CreateNatTable(v, tableName string) error {
	return createTable(v, tableName)
}

func createTable(v, tableName string) error {
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
