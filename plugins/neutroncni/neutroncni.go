package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"os/exec"
	"strings"

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

func UpdateNeutronPort(client *gophercloud.ServiceClient, portID string, containerID string) (*ports.Port, error) {
	//TODO
	host := "cc-zyktest-x86-controller-2"
	deviceOwner := "kubernetes"
	opts := UpdateOpts{
		DeviceID:    &containerID,
		DeviceOwner: &deviceOwner,
		BindHost:    &host,
	}
	port, err := ports.Update(client, portID, opts).Extract()
	if err != nil {
		// handle error
		// fmt.Printf("error: %v\n", err)
		return nil, err
	}
	return port, nil
}

func setUpContVethPair(hostIfName, contIfName string, mtu int, mac string, netns ns.NetNS, port *ports.Port, subnet *subnets.Subnet) (netlink.Link, netlink.Link, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostIfName,
			MTU:  mtu,
		},
		PeerName: contIfName,
	}
	if mac != "" {
		m, err := net.ParseMAC(mac)
		if err != nil {
			return nil, nil, err
		}
		veth.PeerHardwareAddr = m
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return nil, nil, err
	}
	// Re-fetch the container link to get its creation-time parameters, e.g. index and mac
	hostIf, err := netlink.LinkByName(hostIfName)
	if err != nil {
		netlink.LinkDel(veth) // try and clean up the link if possible.
		return nil, nil, err
	}

	contIf, err := netlink.LinkByName(contIfName)
	if err != nil {
		netlink.LinkDel(veth) // try and clean up the link if possible.
		return nil, nil, err
	}

	if err = netlink.SetPromiscOn(hostIf); err != nil {
		return nil, nil, fmt.Errorf("faild to set %q promisc on: %v", hostIfName, err)
	}

	if err = netlink.LinkSetUp(hostIf); err != nil {
		return nil, nil, fmt.Errorf("can not set host nic %s up: %v", hostIfName, err)
	}

	if err = netlink.LinkSetTxQLen(hostIf, 1000); err != nil {
		return nil, nil, fmt.Errorf("can not set host nic %s qlen: %v", hostIfName, err)
	}

	// configure container nic
	if err = netlink.LinkSetNsFd(contIf, int(netns.Fd())); err != nil {
		return nil, nil, fmt.Errorf("failed to link netns: %v", err)
	}

	err = ns.WithNetNSPath(netns.Path(), func(_ ns.NetNS) error {
		contIf, err := netlink.LinkByName(contIfName)
		if err != nil {
			netlink.LinkDel(veth) // try and clean up the link if possible.
			return err
		}
		// configure ip
		ip := port.FixedIPs[0].IPAddress
		cidr := subnet.CIDR
		ipStr := fmt.Sprintf("%s/%s", ip, strings.Split(cidr, "/")[1])

		ipAddr, err := netlink.ParseAddr(ipStr)
		if err != nil {
			return fmt.Errorf("can not parse address %s: %v", ipStr, err)
		}

		if err = netlink.AddrAdd(contIf, ipAddr); err != nil {
			return fmt.Errorf("can not add address %v to nic %s: %v", ipAddr, contIf, err)
		}

		if err != nil {
			return fmt.Errorf("failed to configure gateway: %v", err)
		}
		if err := netlink.LinkSetUp(contIf); err != nil {
			return fmt.Errorf("can not set container nic %s up: %v", contIfName, err)
		}

		if err := netlink.LinkSetTxQLen(contIf, 1000); err != nil {
			return fmt.Errorf("can not set container nic %s qlen: %v", contIfName, err)
		}

		return nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to configure container nic %s: %v", contIfName, err)
	}

	return hostIf, contIf, nil
}

func setUpVethPair(qvbName, qvoName string, mtu, qlen int) (netlink.Link, netlink.Link, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: qvbName,
			MTU:  mtu,
		},
		PeerName: qvoName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return nil, nil, err
	}

	qvbVeth, err := netlink.LinkByName(qvbName)
	if err != nil {
		netlink.LinkDel(veth) // try and clean up the link if possible.
		return nil, nil, err
	}

	qvoVeth, err := netlink.LinkByName(qvoName)
	if err != nil {
		netlink.LinkDel(veth) // try and clean up the link if possible.
		return nil, nil, err
	}

	if err := netlink.SetPromiscOn(qvbVeth); err != nil {
		return nil, nil, fmt.Errorf("faild to set %s promisc on: %v", qvbName, err)
	}

	if err := netlink.SetPromiscOn(qvoVeth); err != nil {
		return nil, nil, fmt.Errorf("faild to set %s promisc on: %v", qvoName, err)
	}

	if err := netlink.LinkSetUp(qvbVeth); err != nil {
		return nil, nil, fmt.Errorf("failed to set %s up: %v", qvbName, err)
	}

	if err := netlink.LinkSetUp(qvoVeth); err != nil {
		return nil, nil, fmt.Errorf("failed to set %s up: %v", qvoName, err)
	}

	if err := netlink.LinkSetTxQLen(qvbVeth, qlen); err != nil {
		return nil, nil, fmt.Errorf("can not set qvb nic %s qlen: %v", qvbName, err)
	}

	if err := netlink.LinkSetTxQLen(qvoVeth, qlen); err != nil {
		return nil, nil, fmt.Errorf("can not set qvo nic %s qlen: %v", qvoName, err)
	}

	return qvbVeth, qvoVeth, err
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
	subnetID := "5670bbfe-4798-44b2-9fa8-5342db96a3c0"
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

	port, err := UpdateNeutronPort(neutronClient, portID, args.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to update port %s: %v", portID, err)
	}

	subnet, err := subnets.Get(neutronClient, subnetID).Extract()
	if err != nil {
		return fmt.Errorf("failed to get subnet %s: %v", subnetID, err)
	}
	// create veth
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %s: %v", args.Netns, err)
	}
	defer netns.Close()

	// get mac
	// TODO
	hostIfName := fmt.Sprintf("tap%s", portPrefix)
	containerIfName := args.IfName

	hostIf, _, err := setUpContVethPair(hostIfName, containerIfName, 1450, port.MACAddress, netns, port, subnet)
	defer func() {
		if err != nil {
			hostIf, _ := netlink.LinkByName(hostIfName)
			if hostIf != nil {
				netlink.LinkDel(hostIf)
			}
		}
	}()
	if err != nil {
		return fmt.Errorf("failed to set up container veth: %v", err)
	}
	// create qbr
	qbrName := fmt.Sprintf("qbr%s", portPrefix)
	qbr, err := setUpBridge(qbrName, 1450, true, false)
	defer func() {
		if err != nil {
			qbr, _ := netlink.LinkByName(qbrName)
			if qbr != nil {
				netlink.LinkDel(qbr)
			}
		}
	}()
	if err != nil {
		return fmt.Errorf("failed to set up bridge %s: %v", qbr.Name, err)
	}

	// connect host veth end to the bridge
	if err := netlink.LinkSetMaster(hostIf, qbr); err != nil {
		return fmt.Errorf("failed to connect %s to bridge %s: %v", hostIfName, qbrName, err)
	}

	// create qvb,qvo
	qvbName := fmt.Sprintf("qvb%s", portPrefix)
	qvoName := fmt.Sprintf("qvo%s", portPrefix)

	qvb, _, err := setUpVethPair(qvbName, qvoName, 1450, 1000)
	defer func() {
		if err != nil {
			qvb, _ := netlink.LinkByName(qvbName)
			if qvb != nil {
				netlink.LinkDel(qvb)
			}
		}
	}()
	if err != nil {
		return fmt.Errorf("failed set up qvb qvo: %v", err)
	}

	// connect qvb veth to the bridge
	if err := netlink.LinkSetMaster(qvb, qbr); err != nil {
		return fmt.Errorf("failed to connect %s to bridge %s: %v", qvbName, qbrName, err)
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

	// TODO
	// configure gateway
	/*
		gateway := "192.168.11.4"
		// configure gateway
		_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
		err = netlink.RouteReplace(&netlink.Route{
			LinkIndex: contIf.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       defaultNet,
			Gw:        net.ParseIP(gateway),
		})
	*/

	result := current.Result{CNIVersion: conf.CNIVersion}
	podIface := current.Interface{
		Name: containerIfName,
		Mac:  mac,
	}
	portIP := port.FixedIPs[0]
	gateway := subnet.GatewayIP
	_, mask, _ := net.ParseCIDR(subnet.CIDR)
	ip := current.IPConfig{
		Address: net.IPNet{IP: net.ParseIP(portIP.IPAddress), Mask: mask.Mask},
		Gateway: net.ParseIP(gateway).To4(),
	}
	route := types.Route{
		Dst: net.IPNet{IP: net.ParseIP("0.0.0.0").To4(), Mask: net.CIDRMask(0, 32)},
		GW:  net.ParseIP(gateway).To4(),
	}
	result.IPs = []*current.IPConfig{&ip}
	result.Routes = []*types.Route{&route}
	result.Interfaces = []*current.Interface{&podIface}
	// Pass through the result for the next plugin
	return types.PrintResult(&result, conf.CNIVersion)
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
	hostIfName := fmt.Sprintf("tap%s", portPrefix)
	hostIfLink, err := netlink.LinkByName(hostIfName)
	if err != nil {
		// If link already not exists, return quietly
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return errors.New("link not found")
		}
		return fmt.Errorf("find qvo veth link %s failed %v", hostIfName, err)
	}
	if err := netlink.LinkDel(hostIfLink); err != nil {
		return fmt.Errorf("delete qbr bridge link %s failed %v", hostIfName, err)
	}
	fmt.Println("cmd del success!")
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	// TODO: implement
	return fmt.Errorf("not implemented")
}
