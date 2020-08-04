package firewall

import (
	"github.com/containernetworking/cni/pkg/version"
)

var supportedVersions = []string{"0.4.0"}

var supportedVersionsMap map[string]struct{}

func init() {
	if supportedVersionsMap == nil {
		supportedVersionsMap = make(map[string]struct{})
	}
	for _, v := range supportedVersions {
		supportedVersionsMap[v] = struct{}{}
	}
}

// GetSupportedVersions returns supported CNI spec versions.
func GetSupportedVersions() version.PluginInfo {
	return version.PluginSupports("0.4.0")
}
