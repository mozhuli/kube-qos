// +build linux

/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bandwidth

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/mozhuli/kube-qos/pkg/exec"
	"github.com/mozhuli/kube-qos/pkg/sets"

	"github.com/golang/glog"
)

// tcShaper provides an implementation of the BandwidthShaper interface on Linux using the 'tc' tool.
// In general, using this requires that the caller posses the NET_CAP_ADMIN capability, though if you
// do this within an container, it only requires the NS_CAPABLE capability for manipulations to that
// container's network namespace.
// Uses the hierarchical token bucket queuing discipline (htb), this requires Linux 2.4.20 or newer
// or a custom kernel with that queuing discipline backported.
type tcShaper struct {
	e     exec.Interface
	iface string
}

func NewTCShaper(iface string) BandwidthShaper {
	shaper := &tcShaper{
		e:     exec.New(),
		iface: iface,
	}
	return shaper
}

func (t *tcShaper) execAndLog(cmdStr string, args ...string) error {
	glog.V(4).Infof("Running: %s %s", cmdStr, strings.Join(args, " "))
	cmd := t.e.Command(cmdStr, args...)
	out, err := cmd.CombinedOutput()
	glog.V(4).Infof("Output from tc: %s", string(out))
	return err
}

func (t *tcShaper) nextClassID(ifb string) (int, error) {
	data, err := t.e.Command("tc", "class", "show", "dev", ifb).CombinedOutput()
	if err != nil {
		return -1, err
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	classes := sets.String{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// skip empty lines
		if len(line) == 0 {
			continue
		}
		parts := strings.Split(line, " ")
		// expected tc line:
		// class htb 1:1 root prio 0 rate 1000Kbit ceil 1000Kbit burst 1600b cburst 1600b
		if len(parts) != 14 {
			return -1, fmt.Errorf("unexpected output from tc: %s (%v)", scanner.Text(), parts)
		}
		classes.Insert(parts[2])
	}

	// Make sure it doesn't go forever
	for nextClass := 1; nextClass < 10000; nextClass++ {
		if !classes.Has(fmt.Sprintf("1:%d", nextClass)) {
			return nextClass, nil
		}
	}
	// This should really never happen
	return -1, fmt.Errorf("exhausted class space, please try again")
}

// Legalize  rate, make 3M becomes 3mbit
func legalizeRate(rate string) (string, error) {
	if strings.HasSuffix(rate, "K") {
		rate = strings.Replace(rate, "K", "Kbit", 1)
		return rate, nil
	}
	if strings.HasSuffix(rate, "M") {
		rate = strings.Replace(rate, "M", "Mbit", 1)
		return rate, nil
	}
	if strings.HasSuffix(rate, "G") {
		rate = strings.Replace(rate, "G", "Gbit", 1)
		return rate, nil
	}
	return "", fmt.Errorf("invalid rate: %s", rate)

}

// Legalize  rate, make 3Kbit becomes 3000bit
func plainRate(rate string) string {
	rate = strings.Trim(rate, "bit")
	if strings.HasSuffix(rate, "K") {
		rate = strings.Replace(rate, "K", "000", 1)
		return rate
	}
	if strings.HasSuffix(rate, "M") {
		rate = strings.Replace(rate, "M", "000000", 1)
		return rate
	}
	return rate
}

// Convert a CIDR from text to a hex representation
// Strips any masked parts of the IP, so 1.2.3.4/16 becomes hex(1.2.0.0)/ffffffff
func hexCIDR(cidr string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ip = ip.Mask(ipnet.Mask)
	hexIP := hex.EncodeToString([]byte(ip.To4()))
	hexMask := ipnet.Mask.String()
	return hexIP + "/" + hexMask, nil
}

// Convert a CIDR from hex representation to text, opposite of the above.
func asciiCIDR(cidr string) (string, error) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected CIDR format: %s", cidr)
	}
	ipData, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	ip := net.IP(ipData)

	maskData, err := hex.DecodeString(parts[1])
	mask := net.IPMask(maskData)
	size, _ := mask.Size()

	return fmt.Sprintf("%s/%d", ip.String(), size), nil
}

func findCIDRClass(cidr, ifb string) (class, handle string, found bool, err error) {
	e := exec.New()
	data, err := e.Command("tc", "filter", "show", "dev", ifb).CombinedOutput()
	if err != nil {
		return "", "", false, err
	}

	hex, err := hexCIDR(cidr)
	if err != nil {
		return "", "", false, err
	}
	spec := fmt.Sprintf("match %s", hex)

	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	filter := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "filter") {
			filter = line
			continue
		}
		if strings.Contains(line, spec) {
			parts := strings.Split(filter, " ")
			// expected tc line:
			// filter parent 1: protocol ip pref 1 u32 fh 800::800 order 2048 key ht 800 bkt 0 flowid 1:1
			if len(parts) != 19 {
				return "", "", false, fmt.Errorf("unexpected output from tc: %s %d (%v)", filter, len(parts), parts)
			}
			return parts[18], parts[9], true, nil
		}
	}
	return "", "", false, nil
}

func (t *tcShaper) reconcileRate(class, rate, ifb string) error {
	data, err := t.e.Command("tc", "class", "show", "dev", ifb, "parent", "1:", "classid", class).CombinedOutput()
	if err != nil {
		return err
	}
	line := strings.TrimSpace(string(data))
	parts := strings.Split(line, " ")
	// expected tc line:
	// class htb 1:1 root prio 0 rate 7000Kbit ceil 7000Kbit burst 1598b cburst 1598b
	if len(parts) != 14 {
		return fmt.Errorf("unexpected output from tc: %s %d (%v)", line, len(parts), parts)
	}
	rate, err = legalizeRate(rate)
	if err != nil {
		return err
	}
	if plainRate(parts[7]) != plainRate(rate) {
		glog.V(4).Infof("reconcile %s original rate %s to %s", ifb, parts[7], rate)
		if err := t.execAndLog("tc", "class", "change",
			"dev", ifb,
			"classid", class,
			"htb", "rate", rate); err != nil {
			return err
		}
	}
	return nil
}

func (t *tcShaper) makeNewClass(rate, ifb string) (int, error) {
	class, err := t.nextClassID(ifb)
	if err != nil {
		return -1, err
	}
	if err := t.execAndLog("tc", "class", "add",
		"dev", ifb,
		"parent", "1:",
		"classid", fmt.Sprintf("1:%d", class),
		"htb", "rate", rate); err != nil {
		return -1, err
	}
	return class, nil
}

func (t *tcShaper) Limit(cidr, rate, ifb string) (err error) {
	rate, err = legalizeRate(rate)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Limit CIDR(%s) with bandwidth(%s)  on %s", cidr, rate, ifb)
	var downloadClass, uploadClass int
	if ifb == "ifb1" {
		if downloadClass, err = t.makeNewClass(rate, "ifb1"); err != nil {
			return err
		}
		if err := t.execAndLog("tc", "filter", "add",
			"dev", "ifb1",
			"protocol", "ip",
			"parent", "1:0",
			"prio", "1", "u32",
			"match", "ip", "dst", cidr,
			"flowid", fmt.Sprintf("1:%d", downloadClass)); err != nil {
			return err
		}
	}
	if ifb == "ifb0" {
		if uploadClass, err = t.makeNewClass(rate, "ifb0"); err != nil {
			return err
		}
		if err := t.execAndLog("tc", "filter", "add",
			"dev", "ifb0",
			"protocol", "ip",
			"parent", "1:0",
			"prio", "1", "u32",
			"match", "ip", "src", cidr,
			"flowid", fmt.Sprintf("1:%d", uploadClass)); err != nil {
			return err
		}
	}
	return nil
}

// tests to see if an interface exists, if it does, return true and the status line for the interface
// returns false, "", <err> if an error occurs.
func (t *tcShaper) qdiscExists(vethName string) (bool, bool, error) {
	data, err := t.e.Command("tc", "qdisc", "show", "dev", vethName).CombinedOutput()
	if err != nil {
		return false, false, err
	}
	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	spec1 := "htb 1: root"
	spec2 := "ingress ffff:"
	rootQdisc := false
	ingressQdisc := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}
		if strings.Contains(line, spec1) {
			rootQdisc = true
		}
		if strings.Contains(line, spec2) {
			ingressQdisc = true
		}
	}
	return rootQdisc, ingressQdisc, nil
}

func (t *tcShaper) ReconcileCIDR(cidr, upload, download string) error {
	glog.V(4).Infof("Shaper CIDR %s with upload %s, download %s", cidr, upload, download)
	if download != "" {
		class, _, found, err := findCIDRClass(cidr, "ifb1")
		if err != nil {
			return err
		}
		if !found {
			return t.Limit(cidr, download, "ifb1")
		}
		if err := t.reconcileRate(class, download, "ifb1"); err != nil {
			return err
		}

	}
	if upload != "" {
		class, _, found, err := findCIDRClass(cidr, "ifb0")
		if err != nil {
			return err
		}
		if !found {
			return t.Limit(cidr, upload, "ifb0")
		}
		if err := t.reconcileRate(class, upload, "ifb0"); err != nil {
			return err
		}
	}
	// TODO: actually check bandwidth limits here
	return nil
}

func (t *tcShaper) ReconcileInterface(upload, download string) error {
	rootQdisc, ingressQdisc, err := t.qdiscExists(t.iface)
	if err != nil {
		return err
	}
	if download != "" {
		if !rootQdisc {
			glog.V(4).Info("Didn't find root qdisc, creating")
			if err := t.execAndLog("tc", "qdisc", "add", "dev", t.iface, "root", "handle", "1:", "htb", "default", "30"); err != nil {
				return err
			}
			if err := t.execAndLog("tc", "filter", "add", "dev", t.iface, "parent", "1:", "protocol", "ip", "u32", "match", "u32", "0", "0", "flowid", "1:1", "action", "mirred", "egress", "redirect", "dev", "ifb1"); err != nil {
				return err
			}
		}
	}
	if upload != "" {
		if !ingressQdisc {
			glog.V(4).Info("Didn't find ingress qdisc, creating")
			if err := t.execAndLog("tc", "qdisc", "add", "dev", t.iface, "ingress"); err != nil {
				return err
			}
			if err := t.execAndLog("tc", "filter", "add", "dev", t.iface, "parent", "ffff:", "protocol", "ip", "u32", "match", "u32", "0", "0", "flowid", "1:1", "action", "mirred", "egress", "redirect", "dev", "ifb0"); err != nil {
				return err
			}
		}
	}
	return nil
}

// Remove a bandwidth limit for a particular CIDR on a particular network interface
func reset(cidr, ifb string) error {
	e := exec.New()
	class, handle, found, err := findCIDRClass(cidr, ifb)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("Failed to find cidr: %s on interface: %s", cidr, ifb)
	}
	glog.V(4).Infof("Delete  filter of %s on ifb0", cidr)
	if _, err := e.Command("tc", "filter", "del",
		"dev", ifb,
		"parent", "1:",
		"proto", "ip",
		"prio", "1",
		"handle", handle, "u32").CombinedOutput(); err != nil {
		return err
	}
	glog.V(4).Infof("Delete  class of %s on ifb0", cidr)
	if _, err := e.Command("tc", "class", "del", "dev", ifb, "parent", "1:", "classid", class).CombinedOutput(); err != nil {
		return err
	}
	return nil
}

func (t *tcShaper) deleteInterface(class, ifb string) error {
	return t.execAndLog("tc", "qdisc", "delete", "dev", ifb, "root", "handle", class)
}

func getCIDRs(ifb string) ([]string, error) {
	e := exec.New()
	data, err := e.Command("tc", "filter", "show", "dev", ifb).CombinedOutput()
	if err != nil {
		return nil, err
	}

	result := []string{}
	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}
		if strings.Contains(line, "match") {
			parts := strings.Split(line, " ")
			// expected tc line:
			// match <cidr> at <number>
			if len(parts) != 4 {
				return nil, fmt.Errorf("unexpected output: %v", parts)
			}
			cidr, err := asciiCIDR(parts[1])
			if err != nil {
				return nil, err
			}
			result = append(result, cidr)
		}
	}
	return result, nil
}

func DeleteExtraLimits(egressPodsCIDRs, ingressPodsCIDRs []string) error {
	//delete extra limits of egress
	egressCIDRsets := sliceToSets(egressPodsCIDRs)
	ifb0CIDRs, err := getCIDRs("ifb0")
	if err != nil {
		return err
	}
	for _, ifb0CIDR := range ifb0CIDRs {
		if !egressCIDRsets.Has(ifb0CIDR) {
			if err := reset(ifb0CIDR, "ifb0"); err != nil {
				return err
			}
		}
	}
	//delete extra limits of ingress
	ingressCIDRsets := sliceToSets(ingressPodsCIDRs)
	ifb1CIDRs, err := getCIDRs("ifb1")
	if err != nil {
		return err
	}
	for _, ifb1CIDR := range ifb1CIDRs {
		if !ingressCIDRsets.Has(ifb1CIDR) {
			if err := reset(ifb1CIDR, "ifb1"); err != nil {
				return err
			}
		}
	}
	return nil
}

func sliceToSets(slice []string) sets.String {
	ss := sets.String{}
	for _, s := range slice {
		ss.Insert(s)
	}
	return ss
}

func InitIfbModule() error {
	e := exec.New()
	if _, err := e.Command("modprobe", "ifb").CombinedOutput(); err != nil {
		return err
	}
	if _, err := e.Command("ip", "link", "set", "dev", "ifb0", "up").CombinedOutput(); err != nil {
		return err
	}
	if _, err := e.Command("ip", "link", "set", "dev", "ifb1", "up").CombinedOutput(); err != nil {
		return err
	}
	if err := initIfb("ifb0"); err != nil {
		return err
	}
	if err := initIfb("ifb1"); err != nil {
		return err
	}
	return nil
}

func initIfb(ifb string) error {
	e := exec.New()
	data, err := e.Command("tc", "qdisc", "show", "dev", ifb).CombinedOutput()
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	spec := "htb 1:"
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}
		if strings.Contains(line, spec) {
			return nil
		}
	}
	if _, err := e.Command("tc", "qdisc", "add", "dev", ifb, "root", "handle", "1:", "htb", "default", "30").CombinedOutput(); err != nil {
		return err
	}
	return nil
}
