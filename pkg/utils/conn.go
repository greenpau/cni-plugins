package utils

import (
	"github.com/google/nftables"
	"github.com/vishvananda/netns"
)

func initNftConn() (*nftables.Conn, error) {
	ns, err := netns.Get()
	if err != nil {
		return nil, err
	}
	conn := &nftables.Conn{
		NetNS: int(ns),
	}
	return conn, nil
}
