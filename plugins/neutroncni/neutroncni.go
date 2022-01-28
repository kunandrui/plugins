package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"os/exec"

	"net"

	"github.com/vishvananda/netlink"
	"runtime"
	"syscall"
)

const (
	OvsVsCtl = "ovs-vsctl"
)

type OSAuthOptions struct {
	IdentityEndpoint string `json:"identity_endpoint"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	DomainName       string `json:"domain_name"`
	ProjectName      string `json:"project_name"`
}

type PluginConf struct {
	// This embeds the standard NetConf structure which allows your plugin
	// to more easily parse standard fields like Name, Type, CNIVersion,
	// and PrevResult.
	types.NetConf

	OSAuthOptions OSAuthOptions `json:"os_auth_options"`
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func main() {
	// replace TODO with your plugin name
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("neutronCNI"))
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	fmt.Println(conf.OSAuthOptions)

	return &conf, nil
}

type UpdateOpts struct {
	Name                *string              `json:"name,omitempty"`
	Description         *string              `json:"description,omitempty"`
	AdminStateUp        *bool                `json:"admin_state_up,omitempty"`
	FixedIPs            interface{}          `json:"fixed_ips,omitempty"`
	DeviceID            *string              `json:"device_id,omitempty"`
	DeviceOwner         *string              `json:"device_owner,omitempty"`
	SecurityGroups      *[]string            `json:"security_groups,omitempty"`
	AllowedAddressPairs *[]ports.AddressPair `json:"allowed_address_pairs,omitempty"`
	BindHost            *string              `json:"binding:host_id,omitempty"`
}

func (opts UpdateOpts) ToPortUpdateMap() (map[string]interface{}, error) {
	return gophercloud.BuildRequestBody(opts, "port")
}

func CreateProvider(conf *PluginConf) (*gophercloud.ProviderClient, error) {

	authOpts := gophercloud.AuthOptions{
		IdentityEndpoint: conf.OSAuthOptions.IdentityEndpoint,
		Username:         conf.OSAuthOptions.Username,
		Password:         conf.OSAuthOptions.Password,
		DomainName:       conf.OSAuthOptions.DomainName,
		Scope: &gophercloud.AuthScope{
			ProjectName: conf.OSAuthOptions.ProjectName,
			DomainName:  conf.OSAuthOptions.DomainName,
		},
	}

	provider, err := openstack.AuthenticatedClient(authOpts)
	if err != nil {
		// handle error
		// fmt.Printf("error: %v\n", err)
		return nil, err
	}

	return provider, nil
}

func CreateNeutronClient(provider *gophercloud.ProviderClient) (*gophercloud.ServiceClient, error) {
	client, err := openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{
		Name:   "neutron",
		Region: "RegionOne",
	})

	if err != nil {
		// handle error
		// fmt.Printf("error: %v\n", err)
		return nil, err
	}
	return client, nil
}

func GetNeutronPort(client *gophercloud.ServiceClient, portID string) (*ports.Port, error) {
	port, err := ports.Get(client, portID).Extract()
	if err != nil {
		// handle error
		// fmt.Printf("error: %v\n", err)
		return nil, err
	}
	return port, nil
}

func UpdateNeutronPort(client *gophercloud.ServiceClient, portID string) (*ports.Port, error) {
	//TODO
	host := "cc-zyktest-x86-controller-2"
	opts := UpdateOpts{
		BindHost: &host,
	}
	port, err := ports.Update(client, portID, opts).Extract()
	if err != nil {
		// handle error
		// fmt.Printf("error: %v\n", err)
		return nil, err
	}
	return port, nil
}

func setupVethPair(portID, ifName, mac string, mtu int) (string, string, error) {
	var err error
	hostNicName, containerNicName := generateNicName(portID, ifName)

	veth := netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: hostNicName}, PeerName: containerNicName}
	if mtu > 0 {
		veth.MTU = mtu
	}
	if mac != "" {
		m, err := net.ParseMAC(mac)
		if err != nil {
			return "", "", err
		}
		veth.LinkAttrs.HardwareAddr = m
	}
	if err = netlink.LinkAdd(&veth); err != nil {
		if err := netlink.LinkDel(&veth); err != nil {
			return "", "", err
		}
		return "", "", fmt.Errorf("failed to crate veth for %v", err)
	}
	return hostNicName, containerNicName, nil
}

func generateNicName(portID, ifname string) (string, string) {
	if ifname == "eth0" {
		return fmt.Sprintf("veth%s_h", portID[0:11]), fmt.Sprintf("veth%s_c", portID[0:11])
	}
	return fmt.Sprintf("%s_%s_h", portID[0:11-len(ifname)], ifname), fmt.Sprintf("%s_%s_c", portID[0:11-len(ifname)], ifname)
}

func configureHostNic(nicName string) error {
	hostLink, err := netlink.LinkByName(nicName)
	if err != nil {
		return fmt.Errorf("can not find host nic %s: %v", nicName, err)
	}

	if hostLink.Attrs().OperState != netlink.OperUp {
		if err = netlink.LinkSetUp(hostLink); err != nil {
			return fmt.Errorf("can not set host nic %s up: %v", nicName, err)
		}
	}
	if err = netlink.LinkSetTxQLen(hostLink, 1000); err != nil {
		return fmt.Errorf("can not set host nic %s qlen: %v", nicName, err)
	}

	return nil
}

func configureContainerNic(nicName, ifName, netns ns.NetNS) error {
	containerLink, err := netlink.LinkByName(nicName)
	if err != nil {
		return fmt.Errorf("can not find container nic %s: %v", nicName, err)
	}

	// Set link alias to its origin link name for fastpath to recognize and bypass netfilter
	if err := netlink.LinkSetAlias(containerLink, nicName); err != nil {
		return err
	}

	if err = netlink.LinkSetNsFd(containerLink, int(netns.Fd())); err != nil {
		return fmt.Errorf("failed to link netns: %v", err)
	}

	return nil
}

func makeVethPair(name, peer string, mtu int, mac string) (netlink.Link, netlink.Link, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
			MTU:  mtu,
		},
		PeerName: peer,
	}
	if mac != "" {
		m, err := net.ParseMAC(mac)
		if err != nil {
			return nil, nil, err
		}
		veth.LinkAttrs.HardwareAddr = m
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, nil, err
	}
	// Re-fetch the container link to get its creation-time parameters, e.g. index and mac
	veth1, err := netlink.LinkByName(name)
	if err != nil {
		netlink.LinkDel(veth) // try and clean up the link if possible.
		return nil, nil, err
	}

	veth2, err := netlink.LinkByName(peer)
	if err != nil {
		netlink.LinkDel(veth) // try and clean up the link if possible.
		return nil, nil, err
	}

	if err = netlink.LinkSetUp(veth1); err != nil {
		return nil, nil, fmt.Errorf("failed to set %v up: %v", veth1, err)
	}

	if err = netlink.LinkSetUp(veth2); err != nil {
		return nil, nil, fmt.Errorf("failed to set %v up: %v", veth2, err)
	}

	return veth1, veth2, nil
}

func bridgeByName(name string) (*netlink.Bridge, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("could not lookup %q: %v", name, err)
	}
	br, ok := l.(*netlink.Bridge)
	if !ok {
		return nil, fmt.Errorf("%q already exists but is not a bridge", name)
	}
	return br, nil
}

func setUpBridge(brName string, mtu int, promiscMode, vlanFiltering bool) (*netlink.Bridge, error) {
	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: brName,
			MTU:  mtu,
			// Let kernel use default txqueuelen; leaving it unset
			// means 0, and a zero-length TX queue messes up FIFO
			// traffic shapers which use TX queue length as the
			// default packet limit
			TxQLen: -1,
		},
	}
	if vlanFiltering {
		br.VlanFiltering = &vlanFiltering
	}

	err := netlink.LinkAdd(br)
	if err != nil && err != syscall.EEXIST {
		return nil, fmt.Errorf("could not add %q: %v", brName, err)
	}

	if promiscMode {
		if err := netlink.SetPromiscOn(br); err != nil {
			return nil, fmt.Errorf("could not set promiscuous mode on %q: %v", brName, err)
		}
	}

	// Re-fetch link to read all attributes and if it already existed,
	// ensure it's really a bridge with similar configuration
	br, err = bridgeByName(brName)
	if err != nil {
		return nil, err
	}

	if err := netlink.LinkSetUp(br); err != nil {
		return nil, err
	}

	return br, nil
}

// cmdAdd is called for ADD requests
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	// TODO
	portID := "ccf9148b-2b73-46c1-b80d-fb7d7f79209d"
	portPrefix := portID[0:11]
	// update port
	provider, err := CreateProvider(conf)
	if err != nil {
		return fmt.Errorf("failed to create provider: %v", err)
	}
	neutronClient, err := CreateNeutronClient(provider)
	if err != nil {
		return fmt.Errorf("failed to create neutron client: %v", err)
	}

	port, err := UpdateNeutronPort(neutronClient, portID)
	if err != nil {
		return fmt.Errorf("failed to update port %s: %v", portID, err)
	}

	// create veth
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %s: %v", args.Netns, err)
	}
	defer netns.Close()

	// get mac
	// TODO
	hostIfName, containerIfName, err := setupVethPair(portID, args.IfName, port.MACAddress, 1450)

	if err = configureHostNic(hostIfName); err != nil {
		return fmt.Errorf("failed to configure %s: %v", hostIfName, err)
	}

	if err = configureContainerNic(containerIfName, args.IfName, netns); err != nil {
		return fmt.Errorf("failed to configure %s: %v", containerIfName, err)
	}

	// create qbr
	qbrName := fmt.Sprintf("qbr%s", portPrefix)
	qbr, err := setUpBridge(qbrName, 1450, false, false)
	if err != nil {
		return fmt.Errorf("failed to set up bridge %s: %v", qbr.Name, err)
	}

	// need to lookup hostVeth again as its index has changed during ns move
	hostVeth, err := netlink.LinkByName(hostIfName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", hostIfName, err)
	}
	//hostIface.Mac = hostVeth.Attrs().HardwareAddr.String()

	// connect host veth end to the bridge
	if err := netlink.LinkSetMaster(hostVeth, qbr); err != nil {
		return fmt.Errorf("failed to connect %s to bridge %s: %v", hostVeth.Attrs().Name, qbr.Attrs().Name, err)
	}

	// create qvb,qvo
	qvbName := fmt.Sprintf("qvb%s", portPrefix)
	qvoName := fmt.Sprintf("qvo%s", portPrefix)
	qvbVeth, qvoVeth, err := makeVethPair(qvbName, qvoName, 1450, "")

	// set qvo promisc on
	if err := netlink.SetPromiscOn(qvbVeth); err != nil {
		return fmt.Errorf("faild to set %q promisc on: %v", qvbName, err)
	}

	// connect qvb veth end to the bridge
	if err := netlink.LinkSetMaster(qvbVeth, qbr); err != nil {
		return fmt.Errorf("failed to connect %s to bridge %s: %v", qvbName, qbrName, err)
	}

	// set qvo promisc on
	if err := netlink.SetPromiscOn(qvoVeth); err != nil {
		return fmt.Errorf("faild to set %q promisc on: %v", qvoName, err)
	}

	// connect qvo veth end to ovs

	/*
		['--', '--if-exists', 'del-port', dev, '--',
		'add-port', bridge, dev,
		'--', 'set', 'Interface', dev,
		'external-ids:iface-id=%s' % iface_id,
		'external-ids:iface-status=active',
		'external-ids:attached-mac=%s' % mac,
		'external-ids:vm-uuid=%s' % instance_id]
	*/

	mac := port.MACAddress
	vmID := args.ContainerID
	ovsArgs := []string{"--", "--if-exists", "del-port", qvoName, "--",
		"add-port", "br-int", qvoName,
		"--", "set", "Interface", qvoName,
		fmt.Sprintf("external-ids:iface-id=%s", portID),
		fmt.Sprintf("external-ids:iface-status=%s", "active"),
		fmt.Sprintf("external-ids:attached-mac=%s", mac),
		fmt.Sprintf("external-ids:vm-uuid=%s", vmID),
	}

	output, err := exec.Command(OvsVsCtl, ovsArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ovs add port failed %q: %v", output, err)
	}

	/*
		result := &current.Result{
			CNIVersion: conf.CNIVersion,
		}
	*/
	fmt.Println("cmd add success!")
	// Pass through the result for the next plugin
	return nil
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}
	_ = conf

	portID := "ccf9148b-2b73-46c1-b80d-fb7d7f79209d"
	portPrefix := portID[0:11]
	// delete qvo, qvb
	qvoName := fmt.Sprintf("qvo%s", portPrefix)
	//qvbName := fmt.Sprintf("qvb%s", portPrefix)

	// Do your delete here
	// ovs delete port

	// output, err := ovs.Exec(ovs.IfExists, "--with-iface", "del-port", "br-int", nicName)
	ovsArgs := []string{"--if-exists", "--with-iface", "del-port", "br-int", qvoName}
	output, err := exec.Command(OvsVsCtl, ovsArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ovs del port failed %q: %v", output, err)
	}

	// delete qvo,qvb
	qvoVeth, err := netlink.LinkByName(qvoName)
	if err != nil {
		// If link already not exists, return quietly
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return errors.New("link not found")
		}
		return fmt.Errorf("find qvo veth link %s failed %v", qvoName, err)
	}
	if err = netlink.LinkDel(qvoVeth); err != nil {
		return fmt.Errorf("delete qvo veth link %s failed %v", qvoName, err)
	}

	// delete qbr
	qbrName := fmt.Sprintf("qbr%s", portPrefix)
	qbr, err := netlink.LinkByName(qbrName)
	if err != nil {
		// If link already not exists, return quietly
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("find qbr bridge link %s failed %v", qbrName, err)
	}
	if err = netlink.LinkDel(qbr); err != nil {
		return fmt.Errorf("delete qbr bridge link %s failed %v", qbrName, err)
	}

	// delete contIface
	hostIfaceName := fmt.Sprintf("veth%s", portPrefix)
	hostIfaceLink, err := netlink.LinkByName(hostIfaceName)
	if err != nil {
		// If link already not exists, return quietly
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return errors.New("link not found")
		}
		return fmt.Errorf("find qvo veth link %s failed %v", hostIfaceName, err)
	}
	if err = netlink.LinkDel(hostIfaceLink); err != nil {
		return fmt.Errorf("delete qbr bridge link %s failed %v", hostIfaceName, err)
	}
	fmt.Println("cmd del success!")
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	// TODO: implement
	return fmt.Errorf("not implemented")
}
