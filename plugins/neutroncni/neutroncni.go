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
	DomainID         string `json:"domain_id"`
	ProjectID        string `json:"project_id"`
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
		DomainID:         conf.OSAuthOptions.DomainID,
		TenantID:         conf.OSAuthOptions.ProjectID,
		TenantName:       conf.OSAuthOptions.ProjectName,
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

func setupVeth(netns ns.NetNS, ifName, hostIfName string, mtu int, mac string) (*current.Interface, *current.Interface, error) {
	contIface := &current.Interface{}
	hostIface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		// create the veth pair in the container and move host end into host netns
		hostVeth, containerVeth, err := ip.SetupVethWithName(ifName, hostIfName, mtu, mac, hostNS)
		if err != nil {
			return err
		}
		contIface.Name = containerVeth.Name
		contIface.Mac = containerVeth.HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// need to lookup hostVeth again as its index has changed during ns move
	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup %q: %v", hostIface.Name, err)
	}
	hostIface.Mac = hostVeth.Attrs().HardwareAddr.String()

	return hostIface, contIface, nil
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
	hostIfName := fmt.Sprintf("veth%s", portPrefix)
	mac := port.MACAddress
	vmID := args.ContainerID

	hostIface, _, err := setupVeth(netns, args.IfName, hostIfName, 1450, mac)

	// create qbr
	qbrName := fmt.Sprintf("qbr%s", portPrefix)
	qbr, err := setUpBridge(qbrName, 1450, false, false)
	if err != nil {
		return fmt.Errorf("failed to set up bridge %s: %v", qbr.Name, err)
	}

	// need to lookup hostVeth again as its index has changed during ns move
	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", hostIface.Name, err)
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

	// connect qvb veth end to the bridge
	if err := netlink.LinkSetMaster(qvbVeth, qbr); err != nil {
		return fmt.Errorf("failed to connect %s to bridge %s: %v", qvbVeth.Attrs().Name, qbr.Attrs().Name, err)
	}

	// set qvo promisc on
	if err := netlink.SetPromiscOn(qvoVeth); err != nil {
		return fmt.Errorf("faild to set %q promisc on: %v", qvoVeth.Attrs().Name, err)
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

	/*
		ovsArgs := []string{"--", "--if-exists", "del-port", qvoName, "--",
			"add-port", "br-int", qvoName,
			"--", "set", "Interface", qvoName,
			fmt.Sprintf("external-ids:iface-id=%s", portID),
			fmt.Sprintf("external-ids:iface-status=%s", "active"),
			fmt.Sprintf("external-ids:attached-mac=%s", mac),
			fmt.Sprintf("external-ids:vm-uuid=%s", vmID),
		}

		output, err := exec.Command(OvsVsCtl, ovsArgs...).CombinedOutput()
	*/

	result := &current.Result{
		CNIVersion: conf.CNIVersion,
	}

	// Pass through the result for the next plugin
	return types.PrintResult(result, conf.CNIVersion)
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}
	_ = conf

	// Do your delete here
	// ovs delete port
	// output, err := ovs.Exec(ovs.IfExists, "--with-iface", "del-port", "br-int", nicName)

	portID := "ccf9148b-2b73-46c1-b80d-fb7d7f79209d"
	portPrefix := portID[0:11]
	// delete qvo, qvb
	qvoName := fmt.Sprintf("qvo%s", portPrefix)
	//qvbName := fmt.Sprintf("qvb%s", portPrefix)

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

	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	// TODO: implement
	return fmt.Errorf("not implemented")
}
