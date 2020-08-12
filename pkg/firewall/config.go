package firewall

import (
	"encoding/json"
	"fmt"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

// Config holds the configuration for the Plugin.
type Config struct {
	types.NetConf
	ContainerID      string `json:"-"`
	FilterTableName  string `json:"filter_table_name"`
	ForwardChainName string `json:"forward_chain_name"`
}

func parseConfigFromBytes(data []byte) (*Config, *current.Result, error) {
	conf := &Config{}
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, nil, fmt.Errorf("failed to load conf: %v", err)
	}

	if _, exists := supportedVersionsMap[conf.CNIVersion]; !exists {
		return nil, nil, fmt.Errorf("unsupported CNI version %s", conf.CNIVersion)
	}

	// Default the filter table name to filter
	if conf.FilterTableName == "" {
		conf.FilterTableName = "filter"
	}

	// Default the forwarding chain name to forward
	if conf.ForwardChainName == "" {
		conf.ForwardChainName = "forward"
	}

	// Parse previous result.
	if conf.RawPrevResult == nil {
		// return early if there was no previous result, which is allowed for DEL calls
		return conf, &current.Result{}, nil
	}

	// Parse previous result.
	var result *current.Result
	var err error
	if err = version.ParsePrevResult(&conf.NetConf); err != nil {
		return nil, nil, fmt.Errorf("could not parse prevResult: %v", err)
	}

	result, err = current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return nil, nil, fmt.Errorf("could not convert result to current version: %v", err)
	}

	return conf, result, nil
}
