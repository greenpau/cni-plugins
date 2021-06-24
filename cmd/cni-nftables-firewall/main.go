// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

package main

import (
	"flag"
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/greenpau/cni-plugins/pkg/firewall"
	"github.com/greenpau/versioned"
	"os"
)

var (
	app        *versioned.PackageManager
	appVersion string
	gitBranch  string
	gitCommit  string
	buildUser  string
	buildDate  string
)

func init() {
	app = versioned.NewPackageManager("cni-nftables-firewall")
	app.Description = "CNI Firewall Plugin for nftables"
	app.Documentation = "https://github.com/greenpau/cni-plugins/"
	app.SetVersion(appVersion, "1.0.7")
	app.SetGitBranch(gitBranch, "")
	app.SetGitCommit(gitCommit, "")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")
}

func main() {
	var isShowVersion bool

	flag.BoolVar(&isShowVersion, "version", false, "version information")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\n%s - %s\n\n", app.Name, app.Description)
		fmt.Fprintf(os.Stderr, "Usage: %s [arguments]\n\n", app.Name)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nDocumentation: %s\n\n", app.Documentation)
	}

	flag.Parse()

	if isShowVersion {
		fmt.Fprintf(os.Stdout, "%s\n", app.Banner())
		os.Exit(0)
	}

	skel.PluginMain(
		firewall.Add,
		firewall.Check,
		firewall.Delete,
		firewall.GetSupportedVersions(),
		fmt.Sprintf("CNI %s plugin %s", app.Name, app.Version),
	)

	os.Exit(0)
}
