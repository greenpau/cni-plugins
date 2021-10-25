package firewall

import (
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/040"
)

// Add initializes an instance of Plugin and adds necessary
// firewall rules.
func Add(args *skel.CmdArgs) error {
	conf, result, err := parseConfigFromBytes(args.StdinData)
	if err != nil {
		return err
	}

	if conf.PrevResult == nil {
		return fmt.Errorf("missing prevResult from earlier plugin")
	}

	conf.ContainerID = args.ContainerID

	p := NewPlugin(conf)
	if err := p.Add(conf, result); err != nil {
		return err
	}

	if result == nil {
		result = &current.Result{}
	}
	return types.PrintResult(result, conf.CNIVersion)
}

// Check initializes an instance of Plugin and performs
// necessary checks.
func Check(args *skel.CmdArgs) error {
	conf, result, err := parseConfigFromBytes(args.StdinData)
	if err != nil {
		return err
	}

	// Ensure we have previous result.
	if conf.PrevResult == nil {
		return fmt.Errorf("missing prevResult from earlier plugin")
	}

	conf.ContainerID = args.ContainerID

	p := NewPlugin(conf)
	if err := p.Check(conf, result); err != nil {
		return err
	}

	return nil
}

// Delete initializes an instance of Plugin and removes
// firewall rules, if any.
func Delete(args *skel.CmdArgs) error {
	conf, result, err := parseConfigFromBytes(args.StdinData)
	if err != nil {
		return err
	}

	conf.ContainerID = args.ContainerID

	p := NewPlugin(conf)
	if err := p.Delete(conf, result); err != nil {
		return err
	}

	return nil
}
