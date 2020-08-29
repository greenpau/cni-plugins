package portmap

import (
	"fmt"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/greenpau/cni-plugins/pkg/utils"
	"net"
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

	// Add post-routing rules
	for _, targetInterface := range p.targetInterfaces {
		for _, addr := range targetInterface.addrs {
			chainName := utils.GetChainName("npo", conf.ContainerID)
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
					"none", "none", "none",
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
				p.postRoutingNatChainName,
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
				bridgeIntfName,
			); err != nil {
				return fmt.Errorf(
					"failed creating postrouting rules in ipv%s %s chain of %s table: %s",
					addr.Version, chainName, p.natTableName, err,
				)
			}
		}
	}

	// Add pre-routing rules
	for _, targetInterface := range p.targetInterfaces {
		for _, addr := range targetInterface.addrs {
			chainName := utils.GetChainName("npr", conf.ContainerID)
			exists, err := utils.IsChainExists(addr.Version, p.natTableName, chainName)
			if err != nil {
				return fmt.Errorf(
					"failed obtaining ipv%s prerouting %s chain info: %s",
					addr.Version, chainName, err,
				)
			}
			if !exists {
				if err := utils.CreateChain(
					addr.Version,
					p.natTableName,
					chainName,
					"none", "none", "none",
				); err != nil {
					return fmt.Errorf(
						"failed creating ipv%s prerouting %s chain: %s",
						addr.Version, chainName, err,
					)
				}
			}
			if len(conf.RuntimeConfig.PortMaps) == 0 {
				continue
			}
			if addr.Version == "4" && conf.ContIPv4.String() == "" {
				continue
			}
			if addr.Version == "6" && conf.ContIPv6.String() == "" {
				continue
			}
			if err := utils.CreateJumpRule(
				addr.Version,
				p.natTableName,
				p.preRoutingNatChainName,
				chainName,
			); err != nil {
				return fmt.Errorf(
					"failed creating jump rule from ipv%s prerouting %s chain: %s",
					addr.Version, chainName, err,
				)
			}

			var destAddr net.IPNet
			if addr.Version == "4" {
				destAddr = conf.ContIPv4
			} else {
				destAddr = conf.ContIPv6
			}

			for _, pm := range conf.RuntimeConfig.PortMaps {
				if err := utils.AddDestinationNatRules(
					addr.Version,
					p.natTableName,
					chainName,
					destAddr,
					pm,
				); err != nil {
					return fmt.Errorf(
						"failed creating destination NAT rules in %s chain of %s table for %v: %s",
						chainName, p.natTableName, pm, err,
					)
				}

				if err := utils.AddDestinationNatRewriteRules(
					addr.Version,
					p.rawTableName,
					p.preRoutingRawChainName,
					destAddr,
					pm,
				); err != nil {
					return fmt.Errorf(
						"failed creating destination NAT rewrite rules in %s chain of %s table for %v: %s",
						p.preRoutingRawChainName, p.rawTableName, pm, err,
					)
				}

				// Check whether the rule allowing traffic to leave out of
				// bridge interface, e.g. cni-podman0, exists.
				// If it does not exist, create it.
				if err := utils.AddFilterForwardMappedPortRules(
					addr.Version,
					p.filterTableName,
					p.forwardFilterChainName,
					destAddr,
					bridgeIntfName,
					pm,
				); err != nil {
					return fmt.Errorf(
						"failed creating filter forward mapped port rules in ipv%s %s chain of %s table for %v: %s",
						addr.Version, p.forwardFilterChainName, p.filterTableName, pm, err,
					)
				}

			}

		}
	}

	/*
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
	   ContIPv4: (net.IPNet) 10.88.0.7/16,
	   ContIPv6: (net.IPNet) <nil>
	*/

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
	if err := p.validateInput(conf, prevResult); err != nil {
		return fmt.Errorf("failed validating input: %s", err)
	}

	for v := range p.targetIPVersions {
		exists, err := utils.IsTableExist(v, p.natTableName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s nat table %s info: %s", v, p.natTableName, err)
		}
		if !exists {
			continue
		}
		exists, err = utils.IsChainExists(v, p.natTableName, p.postRoutingNatChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining ipv%s postrouting chain %s info: %s",
				v, p.postRoutingNatChainName, err,
			)
		}
		if exists {
			for _, targetInterface := range p.targetInterfaces {
				for _, addr := range targetInterface.addrs {
					if v != addr.Version {
						continue
					}
					chainName := utils.GetChainName("npo", conf.ContainerID)
					if err := utils.DeleteJumpRule(addr.Version, p.natTableName, p.postRoutingNatChainName, chainName); err != nil {
						return err
					}
				}
			}
		}
	}

	for _, targetInterface := range p.targetInterfaces {
		for _, addr := range targetInterface.addrs {
			chainName := utils.GetChainName("npo", conf.ContainerID)
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
