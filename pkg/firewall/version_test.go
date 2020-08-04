package firewall

import (
	"reflect"
	"testing"
)

func TestSupportedVersion(t *testing.T) {
	info := GetSupportedVersions()
	if !reflect.DeepEqual(info.SupportedVersions(), supportedVersions) {
		t.Fatalf(
			"supported version mismatch: %v (supported) vs. %v (received)",
			supportedVersions, info.SupportedVersions(),
		)
	}
	t.Logf("%v", info.SupportedVersions())
}
