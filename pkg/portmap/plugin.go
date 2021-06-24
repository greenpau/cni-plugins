package portmap

import (
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/greenpau/cni-plugins/pkg/utils"
)

// Interface represents a collection of addresses
// associated with a network interface.
type Interface struct {
	addrs []*current.IPConfig
}

// Plugin represents the nftables port-mapping CNI plugin.
type Plugin struct {
	name                    string
	cniVersion              string
	supportedVersions       []string
	natTableName            string
	postRoutingNatChainName string
	preRoutingNatChainName  string
	outputNatChainName      string
	inputNatChainName       string
	rawTableName            string
	preRoutingRawChainName  string
	filterTableName         string
	forwardFilterChainName  string
	interfaceChain          []string
	targetInterfaces        map[string]*Interface
	targetIPVersions        map[string]bool
}

// NewPlugin returns an instance of Plugin.
func NewPlugin(conf *Config) *Plugin {
	return &Plugin{
		name:                    "cni-nftables-portmap",
		cniVersion:              "0.4.0",
		supportedVersions:       supportedVersions,
		natTableName:            conf.NatTableName,
		postRoutingNatChainName: conf.PostRoutingNatChainName,
		preRoutingNatChainName:  conf.PreRoutingNatChainName,
		outputNatChainName:      conf.OutputNatChainName,
		inputNatChainName:       conf.InputNatChainName,
		rawTableName:            conf.RawTableName,
		preRoutingRawChainName:  conf.PreRoutingRawChainName,
		filterTableName:         conf.FilterTableName,
		forwardFilterChainName:  conf.ForwardFilterChainName,
		targetIPVersions:        make(map[string]bool),
		interfaceChain:          []string{},
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

func (p *Plugin) execAdd(conf *Config, prevResult *current.Result) error {
	if err := p.validateInput(conf, prevResult); err != nil {
		return fmt.Errorf("failed validating input: %s", err)
	}

	for v := range p.targetIPVersions {
		// NAT Table and Chains Setup
		exists, err := utils.IsTableExist(v, p.natTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s %s table info: %s", v, p.natTableName, err)
		}
		if !exists {
			if err := utils.CreateTable(v, p.natTableName); err != nil {
				return fmt.Errorf("failed creating ipv%s %s table: %s", v, p.natTableName, err)
			}
		}

		exists, err = utils.IsChainExists(v, p.natTableName, p.postRoutingNatChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.postRoutingNatChainName, p.natTableName, err,
			)
		}
		if !exists {
			if err := utils.CreateNatPostRoutingChain(v, p.natTableName, p.postRoutingNatChainName); err != nil {
				return fmt.Errorf(
					"failed creating ipv%s %s chain in %s table: %s",
					v, p.postRoutingNatChainName, p.natTableName, err,
				)
			}
		}

		exists, err = utils.IsChainExists(v, p.natTableName, p.preRoutingNatChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.preRoutingNatChainName, p.natTableName, err,
			)
		}
		if !exists {
			if err := utils.CreateNatPreRoutingChain(v, p.natTableName, p.preRoutingNatChainName); err != nil {
				return fmt.Errorf(
					"failed creating ipv%s %s chain in %s table: %s",
					v, p.preRoutingNatChainName, p.natTableName, err,
				)
			}
		}

		exists, err = utils.IsChainExists(v, p.natTableName, p.outputNatChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.outputNatChainName, p.natTableName, err,
			)

		}
		if !exists {
			if err := utils.CreateNatOutputChain(v, p.natTableName, p.outputNatChainName); err != nil {
				return fmt.Errorf(
					"failed creating ipv%s %s chain in %s table: %s",
					v, p.outputNatChainName, p.natTableName, err,
				)
			}
		}

		exists, err = utils.IsChainExists(v, p.natTableName, p.inputNatChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.inputNatChainName, p.natTableName, err,
			)
		}
		if !exists {
			if err := utils.CreateNatInputChain(v, p.natTableName, p.inputNatChainName); err != nil {
				return fmt.Errorf(
					"failed creating ipv%s %s chain in %s table: %s",
					v, p.inputNatChainName, p.natTableName, err,
				)

			}
		}

		// Raw Table and Chains Setup
		exists, err = utils.IsTableExist(v, p.rawTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s %s table info: %s", v, p.rawTableName, err)
		}
		if !exists {
			if err := utils.CreateTable(v, p.rawTableName); err != nil {
				return fmt.Errorf("failed creating ipv%s %s table: %s", v, p.rawTableName, err)
			}
		}

		exists, err = utils.IsChainExists(v, p.rawTableName, p.preRoutingRawChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.preRoutingRawChainName, p.rawTableName, err,
			)
		}
		if !exists {
			if err := utils.CreateRawPreRoutingChain(v, p.rawTableName, p.preRoutingRawChainName); err != nil {
				return fmt.Errorf(
					"failed creating ipv%s %s chain in %s table: %s",
					v, p.preRoutingRawChainName, p.rawTableName, err,
				)
			}
		}

		// Filter Table and Chains Setup
		exists, err = utils.IsTableExist(v, p.filterTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s %s table info: %s", v, p.filterTableName, err)
		}
		if !exists {
			if err := utils.CreateTable(v, p.filterTableName); err != nil {
				return fmt.Errorf("failed creating ipv%s %s table: %s", v, p.filterTableName, err)
			}
		}

		exists, err = utils.IsChainExists(v, p.filterTableName, p.forwardFilterChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.forwardFilterChainName, p.filterTableName, err,
			)
		}
		if !exists {
			if err := utils.CreateFilterForwardChain(v, p.filterTableName, p.forwardFilterChainName); err != nil {
				return fmt.Errorf(
					"failed creating ipv%s %s chain in %s table: %s",
					v, p.forwardFilterChainName, p.filterTableName, err,
				)
			}
		}
	}

	// Set bridge interface name
	bridgeIntfName := p.interfaceChain[0]

	for _, targetInterface := range p.targetInterfaces {
		for _, addr := range targetInterface.addrs {

			if len(conf.RuntimeConfig.PortMaps) == 0 {
				continue
			}
			if addr.Version == "4" && conf.ContIPv4.String() == "" {
				continue
			}
			if addr.Version == "6" && conf.ContIPv6.String() == "" {
				continue
			}

			var loopbackIP net.IP
			var destAddr net.IPNet
			if addr.Version == "4" {
				loopbackIP = net.ParseIP("127.0.0.1")
				destAddr = conf.ContIPv4
			} else {
				loopbackIP = net.ParseIP("::1")
				destAddr = conf.ContIPv6
			}

			nprChain := utils.GetChainName("npr", conf.ContainerID)
			npoChain := utils.GetChainName("npo", conf.ContainerID)

			// Add NPR chain.
			if exists, err := utils.IsChainExists(addr.Version, p.natTableName, nprChain); !exists && err == nil {
				if err := utils.CreateChain(
					addr.Version,
					p.natTableName,
					nprChain,
					"none", "none", "none",
				); err != nil {
					return fmt.Errorf(
						"failed creating ipv%s prerouting %s chain: %s",
						addr.Version, nprChain, err,
					)
				}
			} else if err != nil {
				return fmt.Errorf(
					"failed obtaining ipv%s prerouting %s chain info: %s",
					addr.Version, nprChain, err,
				)
			}

			// Add postrouting chain
			if exists, err := utils.IsChainExists(addr.Version, p.natTableName, npoChain); !exists && err == nil {
				if err := utils.CreateChain(
					addr.Version,
					p.natTableName,
					npoChain,
					"none", "none", "none",
				); err != nil {
					return fmt.Errorf(
						"failed creating ipv%s postrouting %s chain: %s",
						addr.Version, npoChain, err,
					)
				}
			} else if err != nil {
				return fmt.Errorf(
					"failed obtaining ipv%s postrouting %s chain info: %s",
					addr.Version, npoChain, err,
				)
			}

			if r, err := utils.GetJumpRule(addr.Version, p.natTableName, p.postRoutingNatChainName, npoChain); err == nil && r == nil {
				if err := utils.CreateJumpRule(
					addr.Version,
					p.natTableName,
					p.postRoutingNatChainName,
					npoChain,
				); err != nil {
					return fmt.Errorf(
						"failed creating jump rule to ipv%s postrouting %s chain: %s",
						addr.Version, npoChain, err,
					)
				}
			} else if err != nil {
				return fmt.Errorf(
					"failed check for jump rule to ipv%s postrouting %s chain: %s",
					addr.Version, npoChain, err,
				)
			}

			// Add an `ip daddr` jump rule to the NAT prerouting chain.
			if err := utils.CreateJumpRuleWithIPDaddrMatch(
				addr.Version,
				p.natTableName,
				p.preRoutingNatChainName,
				nprChain,
				loopbackIP,
			); err != nil {
				return fmt.Errorf(
					"failed creating jump rule from ipv%s prerouting %s chain: %s",
					addr.Version, nprChain, err,
				)
			}

			// Add an `ip daddr` jump rule to the NAT output chain.
			if err := utils.CreateJumpRuleWithIPDaddrMatch(
				addr.Version,
				p.natTableName,
				p.outputNatChainName,
				nprChain,
				loopbackIP,
			); err != nil {
				return fmt.Errorf(
					"failed creating jump rule from ipv%s output %s chain: %s",
					addr.Version, nprChain, err,
				)
			}

			for _, pm := range conf.RuntimeConfig.PortMaps {
				if err := utils.AddDestinationNatRules(
					map[string]interface{}{
						"version":          addr.Version,
						"table":            p.natTableName,
						"chain":            nprChain,
						"bridge_interface": bridgeIntfName,
						"ip_address":       destAddr,
						"port_mapping":     pm,
					},
				); err != nil {
					return fmt.Errorf(
						"failed creating destination NAT rules in %s chain of %s table for %v: %s",
						nprChain, p.natTableName, pm, err,
					)
				}

				// Check whether the rule allowing traffic to leave out of
				// bridge interface, e.g. cni-podman0, exists.
				// If it does not exist, create it.
				if err := utils.AddFilterForwardMappedPortRules(
					map[string]interface{}{
						"version":          addr.Version,
						"table":            p.filterTableName,
						"chain":            p.forwardFilterChainName,
						"bridge_interface": bridgeIntfName,
						"ip_address":       destAddr,
						"port_mapping":     pm,
					},
				); err != nil {
					return fmt.Errorf(
						"failed creating filter forward mapped port rules in ipv%s %s chain of %s table for %v: %s",
						addr.Version, p.forwardFilterChainName, p.filterTableName, pm, err,
					)
				}
			}

			// Add postrouting nat rules
			if err := utils.AddPostRoutingSourceNatForLocalnet(
				map[string]interface{}{
					"version":          addr.Version,
					"table":            p.natTableName,
					"chain":            npoChain,
					"bridge_interface": bridgeIntfName,
					"ip_address":       destAddr,
				},
			); err != nil {
				return fmt.Errorf(
					"failed creating postrouting rule for localhost ipv%s %s chain of %s table: %s",
					addr.Version, p.forwardFilterChainName, p.filterTableName, err,
				)
			}
		}
	}
	return nil
}

func (p *Plugin) execCheck(conf *Config, prevResult *current.Result) error {
	if err := p.validateInput(conf, prevResult); err != nil {
		return fmt.Errorf("failed validating input: %s", err)
	}

	for v := range p.targetIPVersions {
		// Check NAT table
		exists, err := utils.IsTableExist(v, p.natTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s %s table info: %s", v, p.natTableName, err)
		}
		if !exists {
			return fmt.Errorf("ipv%s table %s does not exist", v, p.natTableName)
		}

		exists, err = utils.IsChainExists(v, p.natTableName, p.postRoutingNatChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.postRoutingNatChainName, p.natTableName, err,
			)
		}
		if !exists {
			return fmt.Errorf(
				"ipv%s chain %s in %s table does not exist",
				v, p.postRoutingNatChainName, p.natTableName,
			)
		}

		exists, err = utils.IsChainExists(v, p.natTableName, p.preRoutingNatChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.preRoutingNatChainName, p.natTableName, err,
			)
		}
		if !exists {
			return fmt.Errorf(
				"ipv%s chain %s in %s table does not exist",
				v, p.preRoutingNatChainName, p.natTableName,
			)
		}

		exists, err = utils.IsChainExists(v, p.natTableName, p.outputNatChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.outputNatChainName, p.natTableName, err,
			)
		}
		if !exists {
			return fmt.Errorf(
				"ipv%s chain %s in %s table does not exist",
				v, p.outputNatChainName, p.natTableName,
			)
		}

		exists, err = utils.IsChainExists(v, p.natTableName, p.inputNatChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.inputNatChainName, p.natTableName, err,
			)
		}
		if !exists {
			return fmt.Errorf(
				"ipv%s chain %s in %s table does not exist",
				v, p.inputNatChainName, p.natTableName,
			)
		}

		// Check Raw table
		exists, err = utils.IsTableExist(v, p.rawTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s %s table info: %s", v, p.rawTableName, err)
		}
		if !exists {
			return fmt.Errorf("ipv%s table %s does not exist", v, p.rawTableName)
		}

		exists, err = utils.IsChainExists(v, p.rawTableName, p.preRoutingRawChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.preRoutingRawChainName, p.rawTableName, err,
			)
		}
		if !exists {
			return fmt.Errorf(
				"ipv%s chain %s in %s table does not exist",
				v, p.preRoutingRawChainName, p.rawTableName,
			)
		}

		// Check Filter table
		exists, err = utils.IsTableExist(v, p.filterTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s %s table info: %s", v, p.filterTableName, err)
		}
		if !exists {
			return fmt.Errorf("ipv%s table %s does not exist", v, p.filterTableName)
		}

		exists, err = utils.IsChainExists(v, p.filterTableName, p.forwardFilterChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining info about ipv%s %s chain in %s table: %s",
				v, p.forwardFilterChainName, p.filterTableName, err,
			)
		}
		if !exists {
			return fmt.Errorf(
				"ipv%s chain %s in %s table does not exist",
				v, p.forwardFilterChainName, p.filterTableName,
			)
		}
	}

	return nil
}

func (p *Plugin) execDelete(conf *Config, prevResult *current.Result) error {
	var err error
	var natTableExists, filterTableExists, forwardFilterChainExists, preRoutingNatChainExists, postRoutingNatChainExists, outputNatChainExists, nprExists, npoExists bool

	if err := p.validateInput(conf, prevResult); err != nil {
		return fmt.Errorf("failed validating input: %s", err)
	}

	nprChain := utils.GetChainName("npr", conf.ContainerID)
	npoChain := utils.GetChainName("npo", conf.ContainerID)
	bridgeIntfName := p.interfaceChain[0]

	for v := range p.targetIPVersions {

		if natTableExists, err = utils.IsTableExist(v, p.natTableName); natTableExists && err == nil {
			if preRoutingNatChainExists, err = utils.IsChainExists(v, p.natTableName, p.preRoutingNatChainName); err != nil {
				return fmt.Errorf(
					"error checking ipv%s prerouting chain %s info: %s",
					v, p.preRoutingNatChainName, err,
				)
			}

			if postRoutingNatChainExists, err = utils.IsChainExists(v, p.natTableName, p.postRoutingNatChainName); err != nil {
				return fmt.Errorf(
					"error checking ipv%s postrouting chain %s info: %s",
					v, p.postRoutingNatChainName, err,
				)
			}

			if outputNatChainExists, err = utils.IsChainExists(v, p.natTableName, p.outputNatChainName); err != nil {
				return fmt.Errorf(
					"error checking ipv%s output chain %s info: %s",
					v, p.outputNatChainName, err,
				)
			}
		} else if err != nil {
			return fmt.Errorf(
				"error checking ipv%s nat table %s info: %s",
				v, p.natTableName, err,
			)
		}

		if filterTableExists, err = utils.IsTableExist(v, p.filterTableName); filterTableExists && err == nil {
			if forwardFilterChainExists, err = utils.IsChainExists(v, p.filterTableName, p.forwardFilterChainName); err != nil {
				return fmt.Errorf(
					"error checking ipv%s forward filter chain %s info: %s",
					v, p.forwardFilterChainName, err,
				)
			}
		} else if err != nil {
			return fmt.Errorf(
				"error checking ipv%s filter table %s info: %s",
				v, p.filterTableName, err,
			)
		}

		for _, targetInterface := range p.targetInterfaces {
			for _, addr := range targetInterface.addrs {
				if v != addr.Version {
					continue
				}

				if nprExists, err = utils.IsChainExists(addr.Version, p.natTableName, nprChain); err != nil {
					return fmt.Errorf(
						"error checking ipv%s prerouting container chain %s info: %s",
						v, nprChain, err,
					)
				}

				if npoExists, err = utils.IsChainExists(addr.Version, p.natTableName, npoChain); err != nil {
					return fmt.Errorf(
						"error checking ipv%s postrouting container chain %s info: %s",
						v, npoChain, err,
					)
				}

				if natTableExists {
					if nprExists {
						if preRoutingNatChainExists {
							if err := utils.DeleteJumpRule(addr.Version, p.natTableName, p.preRoutingNatChainName, nprChain); err != nil {
								return err
							}
						}
						if outputNatChainExists {
							if err := utils.DeleteJumpRule(addr.Version, p.natTableName, p.outputNatChainName, nprChain); err != nil {
								return err
							}
						}
						if err := utils.DeleteChain(addr.Version, p.natTableName, nprChain); err != nil {
							return err
						}
					}
					if npoExists {
						if postRoutingNatChainExists {
							if err := utils.DeleteJumpRule(addr.Version, p.natTableName, p.postRoutingNatChainName, npoChain); err != nil {
								return err
							}
						}
						if err := utils.DeleteChain(addr.Version, p.natTableName, npoChain); err != nil {
							return err
						}
					}
				}

				var destAddr net.IPNet
				if addr.Version == "4" {
					destAddr = conf.ContIPv4
				} else {
					destAddr = conf.ContIPv6
				}

				if filterTableExists && forwardFilterChainExists {
					for _, pm := range conf.RuntimeConfig.PortMaps {
						if err := utils.RemoveFilterForwardMappedPortRules(
							map[string]interface{}{
								"version":          addr.Version,
								"table":            p.filterTableName,
								"chain":            p.forwardFilterChainName,
								"bridge_interface": bridgeIntfName,
								"ip_address":       destAddr,
								"port_mapping":     pm,
							},
						); err != nil {
							return fmt.Errorf(
								"failed removing filter forward mapped port rules in ipv%s %s chain of %s table for %v: %s",
								addr.Version, p.forwardFilterChainName, p.filterTableName, pm, err,
							)
						}
					}
				}
			}
		}
	}
	return nil
}
