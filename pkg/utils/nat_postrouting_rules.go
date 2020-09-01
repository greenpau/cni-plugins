package utils

// AddPostRoutingRules adds a set of rules in postrouting chain of nat table.
func AddPostRoutingRules(opts map[string]interface{}) error {
	v := opts["version"].(string)
	if err := isSupportedIPVersion(v); err != nil {
		return err
	}
	if err := addPostRoutingLocalMulticastRule(opts); err != nil {
		return err
	}
	if err := addPostRoutingBroadcastRule(opts); err != nil {
		return err
	}
	if err := addPostRoutingSourceNatRule(opts); err != nil {
		return err
	}
	return nil
}
