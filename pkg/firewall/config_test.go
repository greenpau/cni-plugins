package firewall

import (
	"github.com/greenpau/cni-plugins/pkg/utils"
	"testing"
)

func TestValidateInput(t *testing.T) {
	var tests = []struct {
		name       string
		path       string
		cniVersion string
		shouldErr  bool
	}{
		{
			name:       "no_errors",
			path:       "testdata/firewall/results/result1.json",
			cniVersion: "0.4.0",
			shouldErr:  false,
		},
		{
			name:       "unsupported_version",
			path:       "testdata/firewall/results/result2.json",
			cniVersion: "0.3.0",
			shouldErr:  true,
		},
		{
			name:       "invalid_json",
			path:       "testdata/firewall/results/result3.json",
			cniVersion: "0.4.0",
			shouldErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b, err := utils.LoadDataFromFilePath(test.path)
			if err != nil {
				t.Error(err)
				return
			}
			conf, result, err := parseConfigFromBytes(b)
			if err != nil && !test.shouldErr {
				t.Error(err)
				return
			}
			if err == nil && test.shouldErr {
				t.Error("succeeded but should fail")
				return
			}
			if err == nil && test.cniVersion != conf.CNIVersion {
				t.Error("succeeded, but found version mismatch")
				return
			}
			t.Logf("%v", conf)
			t.Logf("%v", result)
			return
		})
	}
}
