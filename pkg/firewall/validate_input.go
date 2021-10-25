package firewall

import (
	"fmt"
	current "github.com/containernetworking/cni/pkg/types/040"
)

func (p *Plugin) validateInput(result *current.Result) error {
	if len(result.Interfaces) == 0 {
		return fmt.Errorf("the data passed to firewall plugin did not contain network interfaces")
	}

	p.targetInterfaces = make(map[string]*Interface)

	intfMap := make(map[int]string)
	for i, intf := range result.Interfaces {
		if intf.Name == "" {
			return fmt.Errorf("the data passed to firewall plugin has no bridge name, e.g. cnibr0")
		}
		if _, interfaceExists := p.targetInterfaces[intf.Name]; interfaceExists {
			return fmt.Errorf("found duplicate interface name %s", intf.Name)
		}
		p.interfaceChain = append(p.interfaceChain, intf.Name)
		targetInterface := &Interface{
			addrs: []*current.IPConfig{},
		}
		p.targetInterfaces[intf.Name] = targetInterface
		intfMap[i] = intf.Name
	}

	if len(result.IPs) == 0 {
		return fmt.Errorf("the data passed to firewall plugin has no IP addresses")
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
			delete(p.targetInterfaces, intf)
		}
	}

	for _, entry := range result.IPs {
		if entry.Address.String() == "" {
			return fmt.Errorf("the data passed to firewall plugin has empty IP address")
		}
	}

	return nil
}
