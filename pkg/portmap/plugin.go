package portmap

import (
	"fmt"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/greenpau/cni-plugins/pkg/utils"
	"github.com/vishvananda/netns"
)

// Interface represents a collection of addresses
// associated with a network interface.
type Interface struct {
	addrs []*current.IPConfig
}

// Plugin represents the nftables port-mapping CNI plugin.
type Plugin struct {
	name                 string
	cniVersion           string
	supportedVersions    []string
	natTableName         string
	postRoutingChainName string
	preRoutingChainName  string
	ns                   netns.NsHandle
	targetInterfaces     map[string]*Interface
	targetIPVersions     map[string]bool
}

// NewPlugin returns an instance of Plugin.
func NewPlugin(conf *Config) *Plugin {
	return &Plugin{
		name:                 "cni-nftables-portmap",
		cniVersion:           "0.4.0",
		supportedVersions:    supportedVersions,
		natTableName:         conf.NatTableName,
		postRoutingChainName: conf.PostRoutingChainName,
		preRoutingChainName:  conf.PreRoutingChainName,
		targetIPVersions:     make(map[string]bool),
	}
}

// Add adds portmap rules.
func (p *Plugin) Add(conf *Config, result *current.Result) error {
	if err := p.execAdd(conf, result); err != nil {
		return fmt.Errorf("%s.Add() error: %s", p.name, err)
	}
	return nil
}

// Check checks whether appropriate portmap rules exist.
func (p *Plugin) Check(conf *Config, result *current.Result) error {
	if err := p.execCheck(conf, result); err != nil {
		return fmt.Errorf("%s.Check() error: %s", p.name, err)
	}
	return nil
}

// Delete deletes appropriate portmap rules, if any.
func (p *Plugin) Delete(conf *Config, result *current.Result) error {
	if err := p.execDelete(conf, result); err != nil {
		return fmt.Errorf("%s.Delete() error: %s", p.name, err)
	}
	return nil
}

/*
		conf

	{
	         NetConf: (types.NetConf) {
	          CNIVersion: (string) (len=5) "0.4.0",
	          Name: (string) (len=6) "podman",
	          Type: (string) (len=20) "cni-nftables-portmap",
	          Capabilities: (map[string]bool) (len=1) {
	           (string) (len=12) "portMappings": (bool) true
	          },
	          IPAM: (types.IPAM) {
	           Type: (string) ""
	          },
	          DNS: (types.DNS) {
	           Nameservers: ([]string) <nil>,
	           Domain: (string) "",
	           Search: ([]string) <nil>,
	           Options: ([]string) <nil>
	          },
	          RawPrevResult: (map[string]interface {}) <nil>,
	          PrevResult: (*current.Result)(0xc00007e8f0)({
	           CNIVersion: (string) (len=5) "0.4.0",
	           Interfaces: ([]*current.Interface) (len=3 cap=4) {
	            (*current.Interface)(0xc00012e5d0)({Name:cni-podman0 Mac:c6:af:d9:de:29:82 Sandbox:}),
	            (*current.Interface)(0xc00012e600)({Name:veth73eceb2d Mac:da:d0:0e:3f:ef:e7 Sandbox:}),
	            (*current.Interface)(0xc00012e630)({Name:eth0 Mac:d2:75:52:3d:30:f4 Sandbox:/var/run/netns/cni-d459a64a-fe9a-94fa-6e18-95a44fe5d3ce})
	           },
	           IPs: ([]*current.IPConfig) (len=1 cap=4) {
	            (*current.IPConfig)(0xc000013aa0)({Version:4 Interface:0xc000019b00 Address:{IP:10.88.0.7 Mask:ffff0000} Gateway:10.88.0.1})
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
	          })
	         },
	         SNAT: (*bool)(0xc000019b34)(true),
	         ConditionsV4: (*[]string)(<nil>),
	         ConditionsV6: (*[]string)(<nil>),
	         MarkMasqBit: (*int)(0xc000019b38)(13),
	         ExternalSetMarkChain: (*string)(<nil>),
	         RuntimeConfig: (struct { PortMaps []portmap.MappingEntry "json:\"portMappings,omitempty\"" }) {
	          PortMaps: ([]portmap.MappingEntry) (len=1 cap=4) {
	           (portmap.MappingEntry) {
	            HostPort: (int) 46063,
	            ContainerPort: (int) 80,
	            Protocol: (string) (len=3) "tcp",
	            HostIP: (string) ""
	           }
	          }
	         },
	         ContainerID: (string) (len=42) "dummy-58840a9d-6b09-90db-9bc8-7a8105eb81d6",
	         ContIPv4: (net.IPNet) <nil>,
	         ContIPv6: (net.IPNet) <nil>
	        })

*/

func (p *Plugin) execAdd(conf *Config, prevResult *current.Result) error {
	if err := p.validateInput(conf, prevResult); err != nil {
		return fmt.Errorf("failed validating input: %s", err)
	}

	for v := range p.targetIPVersions {
		exists, err := utils.IsNatTableExist(v, p.natTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s nat table info: %s", v, err)
		}
		if !exists {
			if err := utils.CreateNatTable(v, p.natTableName); err != nil {
				return fmt.Errorf("failed creating ipv%s nat table: %s", v, err)
			}
		}
		exists, err = utils.IsChainExists(v, p.natTableName, p.postRoutingChainName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s postrouting chain info: %s", v, err)
		}
		if !exists {
			if err := utils.CreateNatPostRoutingChain(v, p.natTableName, p.postRoutingChainName); err != nil {
				return fmt.Errorf("failed creating ipv%s postrouting chain: %s", v, err)
			}
		}
	}

	for intfName, targetInterface := range p.targetInterfaces {
		for _, addr := range targetInterface.addrs {
			chainName := utils.GetChainName(conf.ContainerID, p.ns.UniqueId(), intfName)
			exists, err := utils.IsChainExists(addr.Version, p.natTableName, chainName)
			if err != nil {
				return fmt.Errorf(
					"failed obtaining ipv%s postrouting %s chain info: %s",
					addr.Version, chainName, err,
				)
			}
			if !exists {
				if err := utils.CreateChain(
					addr.Version,
					p.natTableName,
					chainName,
				); err != nil {
					return fmt.Errorf(
						"failed creating ipv%s postrouting %s chain: %s",
						addr.Version, chainName, err,
					)
				}
			}
			if err := utils.CreateJumpRule(
				addr.Version,
				p.natTableName,
				p.postRoutingChainName,
				chainName,
			); err != nil {
				return fmt.Errorf(
					"failed creating jump rule to ipv%s postrouting %s chain: %s",
					addr.Version, chainName, err,
				)
			}

			if err := utils.AddPostRoutingRules(
				addr.Version,
				p.natTableName,
				chainName,
				addr,
				intfName,
			); err != nil {
				return fmt.Errorf(
					"failed creating postrouting rules in ipv%s %s chain of %s table: %s",
					addr.Version, chainName, p.natTableName, err,
				)
			}
		}
	}

	/*
			conf looks as follows

		    NetConf: (types.NetConf) {
		     CNIVersion: (string) (len=5) "0.4.0",
		     Name: (string) (len=6) "podman",
		     Type: (string) (len=20) "cni-nftables-portmap",
		     Capabilities: (map[string]bool) (len=1) {
		      (string) (len=12) "portMappings": (bool) true
		     },
		     IPAM: (types.IPAM) {
		      Type: (string) ""
		     },
		     DNS: (types.DNS) {
		      Nameservers: ([]string) <nil>,
		      Domain: (string) "",
		      Search: ([]string) <nil>,
		      Options: ([]string) <nil>
		     },
		     RawPrevResult: (map[string]interface {}) <nil>,
		     PrevResult: (*current.Result)(0xc00007e8f0)({
		      CNIVersion: (string) (len=5) "0.4.0",
		      Interfaces: ([]*current.Interface) (len=3 cap=4) {
		       (*current.Interface)(0xc00012e5d0)({Name:cni-podman0 Mac:c6:af:d9:de:29:82 Sandbox:}),
		       (*current.Interface)(0xc00012e600)({Name:veth73eceb2d Mac:da:d0:0e:3f:ef:e7 Sandbox:}),
		       (*current.Interface)(0xc00012e630)({Name:dummy0 Mac:d2:75:52:3d:30:f4 Sandbox:/var/run/netns/cni-d459a64a-fe9a-94fa-6e18-95a44fe5d3ce})
		      },
		      IPs: ([]*current.IPConfig) (len=1 cap=4) {
		       (*current.IPConfig)(0xc000013aa0)({Version:4 Interface:0xc000019b30 Address:{IP:10.88.0.7 Mask:ffff0000} Gateway:10.88.0.1})
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
		     })
		    },
		    SNAT: (*bool)(0xc000019b64)(true),
		    ConditionsV4: (*[]string)(<nil>),
		    ConditionsV6: (*[]string)(<nil>),
		    MarkMasqBit: (*int)(0xc000019b68)(13),
		    ExternalSetMarkChain: (*string)(<nil>),
		    RuntimeConfig: (struct { PortMaps []portmap.MappingEntry "json:\"portMappings,omitempty\"" }) {
		     PortMaps: ([]portmap.MappingEntry) (len=1 cap=4) {
		      (portmap.MappingEntry) {
		       HostPort: (int) 46063,
		       ContainerPort: (int) 80,
		       Protocol: (string) (len=3) "tcp",
		       HostIP: (string) ""
		      }
		     }
		    },
		    ContainerID: (string) (len=42) "dummy-a2e9ea73-75bb-5c5f-49bd-40acb0b30405",
		    ContIPv4: (net.IPNet) 10.88.0.7/16,
		    ContIPv6: (net.IPNet) <nil>
		   })
	*/

	/*
		if conf.ContIPv4.IP != nil {
			if err := forwardPorts(conf, conf.ContIPv4); err != nil {
				return err
			}
		}
		if conf.ContIPv6.IP != nil {
			if err := forwardPorts(conf, conf.ContIPv6); err != nil {
				return err
			}
		}
	*/
	return nil
}

func (p *Plugin) execCheck(conf *Config, prevResult *current.Result) error {
	if err := p.validateInput(conf, prevResult); err != nil {
		return fmt.Errorf("failed validating input: %s", err)
	}

	for v := range p.targetIPVersions {
		exists, err := utils.IsNatTableExist(v, p.natTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s nat table %s info: %s", v, p.natTableName, err)
		}
		if !exists {
			return fmt.Errorf("ipv%s nat table %s does not exist", v, p.natTableName)
		}
		exists, err = utils.IsChainExists(v, p.natTableName, p.postRoutingChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining ipv%s postrouting chain %s info: %s",
				v, p.postRoutingChainName, err,
			)
		}
		if !exists {
			return fmt.Errorf(
				"ipv%s chain %s in nat table %s does not exist",
				v, p.postRoutingChainName, p.natTableName,
			)
		}
	}

	return nil
}

func (p *Plugin) execDelete(conf *Config, prevResult *current.Result) error {
	if err := p.validateInput(conf, prevResult); err != nil {
		return fmt.Errorf("failed validating input: %s", err)
	}

	for v := range p.targetIPVersions {
		exists, err := utils.IsNatTableExist(v, p.natTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s nat table %s info: %s", v, p.natTableName, err)
		}
		if !exists {
			continue
		}
		exists, err = utils.IsChainExists(v, p.natTableName, p.postRoutingChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining ipv%s postrouting chain %s info: %s",
				v, p.postRoutingChainName, err,
			)
		}
		if exists {
			for intfName, targetInterface := range p.targetInterfaces {
				for _, addr := range targetInterface.addrs {
					if v != addr.Version {
						continue
					}
					chainName := utils.GetChainName(conf.ContainerID, p.ns.UniqueId(), intfName)
					if err := utils.DeleteJumpRule(addr.Version, p.natTableName, p.postRoutingChainName, chainName); err != nil {
						return err
					}
				}
			}
		}
	}

	for intfName, targetInterface := range p.targetInterfaces {
		for _, addr := range targetInterface.addrs {
			chainName := utils.GetChainName(conf.ContainerID, p.ns.UniqueId(), intfName)
			exists, err := utils.IsChainExists(addr.Version, p.natTableName, chainName)
			if err != nil {
				continue
			}
			if exists {
				if err := utils.DeleteChain(addr.Version, p.natTableName, chainName); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
