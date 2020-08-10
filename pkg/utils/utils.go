package utils

import (
	"io/ioutil"
	"path"
	"regexp"
	"strings"
)

// EncodeInterfaceName returns null-terminated string for
// netlink communication.
func EncodeInterfaceName(s string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(s+"\x00"))
	return b
}

// GetChainName returns nftables chain name based
// on the provided namespace and interface.
<<<<<<< HEAD
func GetChainName(containerID, nsID, intf string) string {
	name := "cni" + nsID + intf
	name = strings.ReplaceAll(name, "(", "-")
	name = strings.ReplaceAll(name, ")", "-")
	name = strings.ReplaceAll(name, ":", "-")
	name = name + "-" + containerID
=======
func GetChainName(prefix, containerID string) string {
>>>>>>> portmap
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		return containerID
	}
<<<<<<< HEAD
	name = reg.ReplaceAllString(name, "")
	//if len(name) < 32 {
	if len(name) < 29 {
		return name
	}
	//name = name[len(name)-31:]
	name = "cni" + name[len(name)-28:]
	return name
=======
	containerID = reg.ReplaceAllString(containerID, "")
	name := "cni-" + prefix + "-"
	offset := 31 - len(name)
	if len(containerID) < offset {
		return name + containerID
	}
	name += containerID[len(containerID)-offset:]
	return name

	/*
		if len(name) < 29 {
			return name
		}
		name = "cni" + name[len(name)-28:]
		return name
	*/
>>>>>>> portmap
}

// LoadDataFromFilePath returns the content of a file
// based on the provided file path.
func LoadDataFromFilePath(fp string) ([]byte, error) {
	b, err := ioutil.ReadFile(fp)
	if err == nil {
		return b, err
	}
	return ioutil.ReadFile("../../" + fp)
}

// GetTestContainerID returns the name for a test container.
func GetTestContainerID(s string) string {
	_, containerID := path.Split(s)
	return strings.ReplaceAll(containerID, "cnitest", "dummy")
}
