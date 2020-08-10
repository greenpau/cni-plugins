package portmap

import (
	"encoding/json"
	"fmt"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	// "github.com/davecgh/go-spew/spew"
<<<<<<< HEAD
=======
	"github.com/greenpau/cni-plugins/pkg/utils"
>>>>>>> portmap

	"net"
)

// Config holds the configuration for the Plugin.
type Config struct {
	types.NetConf
	SNAT                 *bool     `json:"snat,omitempty"`
	ConditionsV4         *[]string `json:"conditionsV4"`
	ConditionsV6         *[]string `json:"conditionsV6"`
	MarkMasqBit          *int      `json:"markMasqBit"`
	ExternalSetMarkChain *string   `json:"externalSetMarkChain"`
	RuntimeConfig        struct {
<<<<<<< HEAD
		PortMaps []MappingEntry `json:"portMappings,omitempty"`
=======
		PortMaps []utils.MappingEntry `json:"portMappings,omitempty"`
>>>>>>> portmap
	} `json:"runtimeConfig,omitempty"`

	// These are fields parsed out of the config or the environment;
	// included here for convenience
	ContainerID string    `json:"-"`
	ContIPv4    net.IPNet `json:"-"`
	ContIPv6    net.IPNet `json:"-"`

	NatTableName         string `json:"nat_table_name"`
	PostRoutingChainName string `json:"postrouting_chain_name"`
	PreRoutingChainName  string `json:"prerouting_chain_name"`
}

// MappingEntry holds the port mapping configuration.
<<<<<<< HEAD
=======
/*
>>>>>>> portmap
type MappingEntry struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP,omitempty"`
}
<<<<<<< HEAD
=======
*/
>>>>>>> portmap

// DefaultMarkBit is the default mark bit to signal that
// masquerading is required.
const DefaultMarkBit = 13

func parseConfigFromBytes(data []byte, intfName string) (*Config, *current.Result, error) {
	conf := &Config{}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, nil, fmt.Errorf("failed to load conf: %v", err)
	}

	if _, exists := supportedVersionsMap[conf.CNIVersion]; !exists {
		return nil, nil, fmt.Errorf("unsupported CNI version %s", conf.CNIVersion)
	}

	// Set default values
	if conf.NatTableName == "" {
		conf.NatTableName = "nat"
	}
	if conf.PostRoutingChainName == "" {
		conf.PostRoutingChainName = "postrouting"
	}
	if conf.PreRoutingChainName == "" {
		conf.PreRoutingChainName = "prerouting"
	}

	// Parse previous result.
	var result *current.Result
	if conf.RawPrevResult != nil {
		var err error
		if err = version.ParsePrevResult(&conf.NetConf); err != nil {
			return nil, nil, fmt.Errorf("could not parse prevResult: %v", err)
		}

		result, err = current.NewResultFromResult(conf.PrevResult)
		if err != nil {
			return nil, nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	if conf.SNAT == nil {
		tvar := true
		conf.SNAT = &tvar
	}

	if conf.MarkMasqBit != nil && conf.ExternalSetMarkChain != nil {
		return nil, nil, fmt.Errorf("Cannot specify externalSetMarkChain and markMasqBit")
	}

	if conf.MarkMasqBit == nil {
		bvar := DefaultMarkBit // go constants are "special"
		conf.MarkMasqBit = &bvar
	}

	if *conf.MarkMasqBit < 0 || *conf.MarkMasqBit > 31 {
		return nil, nil, fmt.Errorf("MasqMarkBit must be between 0 and 31")
	}

	// Reject invalid port numbers
	for _, pm := range conf.RuntimeConfig.PortMaps {
		if pm.ContainerPort <= 0 {
			return nil, nil, fmt.Errorf("Invalid container port number: %d", pm.ContainerPort)
		}
		if pm.HostPort <= 0 {
			return nil, nil, fmt.Errorf("Invalid host port number: %d", pm.HostPort)
		}
	}

<<<<<<< HEAD
	//return nil, nil, fmt.Errorf("PARSE: %s", spew.Sdump(conf, result))

=======
>>>>>>> portmap
	if conf.PrevResult != nil {
		for _, ip := range result.IPs {
			if ip.Version == "6" && conf.ContIPv6.IP != nil {
				continue
			} else if ip.Version == "4" && conf.ContIPv4.IP != nil {
				continue
			}

			// Skip known non-sandbox interfaces
			if ip.Interface != nil {
				intIdx := *ip.Interface
				if intIdx >= 0 &&
					intIdx < len(result.Interfaces) &&
					(result.Interfaces[intIdx].Name != intfName ||
						result.Interfaces[intIdx].Sandbox == "") {
					continue

				}
			}

			//return nil, nil, fmt.Errorf("PARSE: %s", spew.Sdump(ip, result.Interfaces))

			switch ip.Version {
			case "6":
				conf.ContIPv6 = ip.Address
			case "4":
				conf.ContIPv4 = ip.Address
			}
		}
	}
	return conf, result, nil
}
