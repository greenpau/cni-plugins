package portmap

import (
	"fmt"
	"github.com/containernetworking/cni/pkg/types/current"
	// "github.com/davecgh/go-spew/spew"
)

func (p *Plugin) validateInput(conf *Config, result *current.Result) error {
	/*
				The result is as follows:
				{
		         CNIVersion: (string) (len=5) "0.4.0",
		         Interfaces: ([]*current.Interface) (len=3 cap=4) {
		          (*current.Interface)(0xc00012e570)({Name:cni-podman0 Mac:c6:af:d9:de:29:82 Sandbox:}),
		          (*current.Interface)(0xc00012e5a0)({Name:vethfb85f49b Mac:7a:ab:ed:a3:39:b1 Sandbox:}),
		          (*current.Interface)(0xc00012e5d0)({Name:eth0 Mac:1a:9a:f0:fe:90:4a Sandbox:/var/run/netns/cni-196ac480-9f0e-3bd7-8f9b-e4a602251bd7})
		         },
		         IPs: ([]*current.IPConfig) (len=1 cap=4) {
		          (*current.IPConfig)(0xc000013aa0)({Version:4 Interface:0xc000019ad0 Address:{IP:10.88.0.5 Mask:ffff0000} Gateway:10.88.0.1})
		         },
		         Routes: ([]*types.Route) (len=1 cap=4) {
		          (*types.Route)(0xc00005c730)({Dst:{IP:0.0.0.0 Mask:00000000} GW:<nil>})
		         },
		         DNS: (types.DNS) {
		          Nameservers: ([]string) <nil>,
		          Domain: (string) "",
		          Search: ([]string) <nil>,
		          Options: ([]string) <nil>
		         }
		        }
	*/

	if len(result.Interfaces) == 0 {
		return fmt.Errorf("the data passed to port mapping plugin did not contain network interfaces")
	}

	p.targetInterfaces = make(map[string]*Interface)

	intfMap := make(map[int]string)
	for i, intf := range result.Interfaces {
		if intf.Name == "" {
			return fmt.Errorf("the data passed to port mapping plugin has no bridge name, e.g. cnibr0")
		}
		if _, interfaceExists := p.targetInterfaces[intf.Name]; interfaceExists {
			return fmt.Errorf("found duplicate interface name %s", intf.Name)
		}
		p.interfaceChain = append(p.interfaceChain, intf.Name)
		if intf.Sandbox == "" {
			continue
		}
		targetInterface := &Interface{
			addrs: []*current.IPConfig{},
		}
		p.targetInterfaces[intf.Name] = targetInterface
		intfMap[i] = intf.Name
	}

	if len(result.IPs) == 0 {
		return fmt.Errorf("the data passed to port mapping plugin has no IP addresses")
	}

	for _, addr := range result.IPs {
		if addr.Interface == nil {
			return fmt.Errorf("the ip config interface is nil: %v", addr)
		}
		if _, interfaceExists := intfMap[*addr.Interface]; !interfaceExists {
			return fmt.Errorf("the ip config points to non-existing interface: %v", addr)
		}
		intfName := intfMap[*addr.Interface]
		targetInterface := p.targetInterfaces[intfName]
		targetInterface.addrs = append(targetInterface.addrs, addr)
		p.targetIPVersions[addr.Version] = true
	}

	for intf, targetInterface := range p.targetInterfaces {
		if targetInterface == nil {
			return fmt.Errorf("interface %s is nil", intf)
		}
		if len(targetInterface.addrs) == 0 {
			return fmt.Errorf("interface %s has no associated IP information: %v", intf, targetInterface)
		}
	}

	for _, entry := range result.IPs {
		if entry.Address.String() == "" {
			return fmt.Errorf("the data passed to port mapping plugin has empty IP address")
		}
	}

	//return fmt.Errorf("debug: %s", spew.Sdump(p.targetInterfaces))

	/*

		The p.targetInterfaces looks as follows ...

		(string) (len=6) "dummy0": (*portmap.Interface)(0xc00000fe80)({
		 addrs: ([]*portmap.InterfaceAddress) (len=1 cap=1) {
		  (*portmap.InterfaceAddress)(0xc00000fea0)({
		   conf: (*current.IPConfig)(0xc000013aa0)({Version:4 Interface:0xc000019b60 Address:{IP:10.88.0.7 Mask:ffff0000} Gateway:10.88.0.1}),
		   table: (*nftables.Table)(<nil>),
		   chain: (*nftables.Chain)(<nil>)
		  })
		 }
		})
		}

	*/

	return nil
}
