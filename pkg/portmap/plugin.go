package portmap

import (
	"fmt"
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
	name                 string
	cniVersion           string
	supportedVersions    []string
	natTableName         string
	postRoutingChainName string
	preRoutingChainName  string
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
		exists, err = utils.IsChainExists(v, p.natTableName, p.preRoutingChainName)
		if err != nil {
			return fmt.Errorf("failed obtaining ipv%s prerouting chain info: %s", v, err)
		}
		if !exists {
			if err := utils.CreateNatPreRoutingChain(v, p.natTableName, p.preRoutingChainName); err != nil {
				return fmt.Errorf("failed creating ipv%s prerouting chain: %s", v, err)
			}
		}
	}

	for intfName, targetInterface := range p.targetInterfaces {
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

	if len(conf.RuntimeConfig.PortMaps) > 0 {
		if err := utils.AddDestinationNatRules(
			p.natTableName,
			p.preRoutingChainName,
			conf.ContIPv4,
			conf.ContIPv6,
			conf.RuntimeConfig.PortMaps,
		); err != nil {
			return fmt.Errorf(
				"failed creating destination NAT rules in %s chain of %s table for %v: %s",
				p.preRoutingChainName, p.natTableName, conf.RuntimeConfig.PortMaps, err,
			)
		}
	}

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
		exists, err = utils.IsChainExists(v, p.natTableName, p.preRoutingChainName)
		if err != nil {
			return fmt.Errorf(
				"failed obtaining ipv%s prerouting chain %s info: %s",
				v, p.preRoutingChainName, err,
			)
		}
		if !exists {
			return fmt.Errorf(
				"ipv%s chain %s in nat table %s does not exist",
				v, p.preRoutingChainName, p.natTableName,
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
			for _, targetInterface := range p.targetInterfaces {
				for _, addr := range targetInterface.addrs {
					if v != addr.Version {
						continue
					}
					chainName := utils.GetChainName("npo", conf.ContainerID)
					if err := utils.DeleteJumpRule(addr.Version, p.natTableName, p.postRoutingChainName, chainName); err != nil {
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
