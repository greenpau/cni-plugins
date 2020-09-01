package portmap

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/greenpau/cni-plugins/pkg/utils"
	"github.com/vishvananda/netlink"
	"path"
	"testing"
)

func TestPlugin(t *testing.T) {
	var tests = []struct {
		name               string
		path               string
		shouldSkip         bool
		shouldDeleteConfig bool
		shouldErr          bool
	}{
		{
			name: "skips configuring nftables when config has no portMappings",
			path: "testdata/portmap/stdindata/stdindata1.json",
			//shouldSkip: true,
			shouldDeleteConfig: false,
		},
		{
			name: "configures destination NAT from host port tcp 46063 to container port 80",
			path: "testdata/portmap/stdindata/stdindata2.json",
			//shouldSkip: true,
			shouldDeleteConfig: false,
		},
		{
			name: "configures destination NAT from host port tcp 46063 to container port 80 and cleans afterwards",
			path: "testdata/portmap/stdindata/stdindata2.json",
			//shouldSkip: true,
			shouldDeleteConfig: true,
		},
	}

	for _, test := range tests {
		if test.shouldSkip {
			continue
		}
		var originalNS, targetNS ns.NetNS
		var err error
		const IFNAME string = "dummy0"
		originalNS, err = testutils.NewNS()
		if err != nil {
			t.Fatalf(err.Error())
		}

		err = originalNS.Do(func(ns.NetNS) error {
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: IFNAME,
				},
			})
			if err != nil {
				return err
			}
			_, err = netlink.LinkByName(IFNAME)
			if err != nil {
				return err
			}
			targetNS, err = testutils.NewNS()
			if err != nil {
				return err
			}
			_, nsName := path.Split(originalNS.Path())
			t.Logf("Container Namespace Path: %s\n", targetNS.Path())
			t.Logf("Debug Namespace:\nsudo ip netns exec %s nft --debug=netlink list ruleset\n", nsName)
			return nil
		})

		if err != nil {
			t.Error(err)
			continue
		}

		t.Run(test.name, func(t *testing.T) {
			b, err := utils.LoadDataFromFilePath(test.path)
			if err != nil {
				t.Error(err)
				return
			}
			conf, result, err := parseConfigFromBytes(b, IFNAME)
			if err != nil {
				t.Error(err)
				return
			}
			t.Logf("%v", conf)
			t.Logf("%v", result)

			args := &skel.CmdArgs{
				ContainerID: utils.GetTestContainerID(targetNS.Path()),
				Netns:       targetNS.Path(),
				IfName:      IFNAME,
				StdinData:   b,
			}

			err = originalNS.Do(func(ns.NetNS) error {
				r, _, err := testutils.CmdAddWithArgs(args, func() error {
					return Add(args)
				})
				if err != nil {
					return err
				}

				_, err = current.GetResult(r)
				if err != nil {
					return err
				}

				err = testutils.CmdCheckWithArgs(args, func() error {
					return Check(args)
				})
				if err != nil {
					return err
				}
				if test.shouldDeleteConfig {
					err = testutils.CmdDelWithArgs(args, func() error {
						return Delete(args)
					})
					if err != nil {
						return err
					}
				}
				return nil
			})

			if err != nil {
				t.Error(err)
			}

			return
		})

	}
}
