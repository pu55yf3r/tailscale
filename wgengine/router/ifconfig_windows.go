/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package router

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"time"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/wgengine/winnet"
)

const (
	sockoptIP_UNICAST_IF   = 31
	sockoptIPV6_UNICAST_IF = 31
)

func htonl(val uint32) uint32 {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, val)
	return *(*uint32)(unsafe.Pointer(&bytes[0]))
}

func bindSocketRoute(family winipcfg.AddressFamily, device *device.Device, ourLuid winipcfg.LUID, lastLuid *winipcfg.LUID) error {
	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return err
	}
	lowestMetric := ^uint32(0)
	index := uint32(0)       // Zero is "unspecified", which for IP_UNICAST_IF resets the value, which is what we want.
	luid := winipcfg.LUID(0) // Hopefully luid zero is unspecified, but hard to find docs saying so.
	for _, route := range routes {
		if route.DestinationPrefix.PrefixLength != 0 || route.InterfaceLUID == ourLuid {
			continue
		}
		if route.Metric < lowestMetric {
			lowestMetric = route.Metric
			index = route.InterfaceIndex
			luid = route.InterfaceLUID
		}
	}
	if luid == *lastLuid {
		return nil
	}
	*lastLuid = luid
	if false {
		bind, ok := device.Bind().(conn.BindSocketToInterface)
		if !ok {
			return fmt.Errorf("unexpected device.Bind type %T", device.Bind())
		}
		// TODO(apenwarr): doesn't work with magic socket yet.
		if family == windows.AF_INET {
			return bind.BindSocketToInterface4(index, false)
		} else if family == windows.AF_INET6 {
			return bind.BindSocketToInterface6(index, false)
		}
	} else {
		log.Printf("WARNING: skipping windows socket binding.")
	}
	return nil
}

func monitorDefaultRoutes(device *device.Device, autoMTU bool, tun *tun.NativeTun) (*winipcfg.RouteChangeCallback, error) {
	guid := tun.GUID()
	ourLuid, err := winipcfg.LUIDFromGUID(&guid)
	lastLuid4 := winipcfg.LUID(0)
	lastLuid6 := winipcfg.LUID(0)
	lastMtu := uint32(0)
	if err != nil {
		return nil, err
	}
	doIt := func() error {
		err = bindSocketRoute(windows.AF_INET, device, ourLuid, &lastLuid4)
		if err != nil {
			return err
		}
		err = bindSocketRoute(windows.AF_INET6, device, ourLuid, &lastLuid6)
		if err != nil {
			log.Printf("bindSocketRoute(AF_INET6): %v", err)
			return err
		}
		if !autoMTU {
			return nil
		}
		mtu := uint32(0)
		if lastLuid4 != 0 {
			iface, err := lastLuid4.Interface()
			if err != nil {
				return err
			}
			if iface.MTU > 0 {
				mtu = iface.MTU
			}
		}
		if lastLuid6 != 0 {
			iface, err := lastLuid6.Interface()
			if err != nil {
				return err
			}
			if iface.MTU > 0 && iface.MTU < mtu {
				mtu = iface.MTU
			}
		}
		if mtu > 0 && (lastMtu == 0 || lastMtu != mtu) {
			iface, err := ourLuid.IPInterface(windows.AF_INET)
			if err != nil {
				return err
			}
			iface.NLMTU = mtu - 80
			// If the TUN device was created with a smaller MTU,
			// though, such as 1280, we don't want to go bigger than
			// configured. (See the comment on minimalMTU in the
			// wgengine package.)
			if min, err := tun.MTU(); err == nil && min < int(iface.NLMTU) {
				iface.NLMTU = uint32(min)
			}
			if iface.NLMTU < 576 {
				iface.NLMTU = 576
			}
			err = iface.Set()
			if err != nil {
				return err
			}
			tun.ForceMTU(int(iface.NLMTU)) //TODO: it sort of breaks the model with v6 mtu and v4 mtu being different. Just set v4 one for now.
			iface, err = ourLuid.IPInterface(windows.AF_INET6)
			if err != nil {
				if !isMissingIPv6Err(err) {
					return err
				}
			} else {
				iface.NLMTU = mtu - 80
				if iface.NLMTU < 1280 {
					iface.NLMTU = 1280
				}
				err = iface.Set()
				if err != nil {
					return err
				}
			}
			lastMtu = mtu
		}
		return nil
	}
	err = doIt()
	if err != nil {
		return nil, err
	}
	cb, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		//fmt.Printf("MonitorDefaultRoutes: changed: %v\n", route.DestinationPrefix)
		if route.DestinationPrefix.PrefixLength == 0 {
			_ = doIt()
		}
	})
	if err != nil {
		return nil, err
	}
	return cb, nil
}

func setFirewall(ifcGUID *windows.GUID) (bool, error) {
	c := ole.Connection{}
	err := c.Initialize()
	if err != nil {
		return false, fmt.Errorf("c.Initialize: %v", err)
	}
	defer c.Uninitialize()

	m, err := winnet.NewNetworkListManager(&c)
	if err != nil {
		return false, fmt.Errorf("winnet.NewNetworkListManager: %v", err)
	}
	defer m.Release()

	cl, err := m.GetNetworkConnections()
	if err != nil {
		return false, fmt.Errorf("m.GetNetworkConnections: %v", err)
	}
	defer cl.Release()

	for _, nco := range cl {
		aid, err := nco.GetAdapterId()
		if err != nil {
			return false, fmt.Errorf("nco.GetAdapterId: %v", err)
		}
		if aid != ifcGUID.String() {
			log.Printf("skipping adapter id: %v", aid)
			continue
		}
		log.Printf("found! adapter id: %v", aid)

		n, err := nco.GetNetwork()
		if err != nil {
			return false, fmt.Errorf("GetNetwork: %v", err)
		}
		defer n.Release()

		cat, err := n.GetCategory()
		if err != nil {
			return false, fmt.Errorf("GetCategory: %v", err)
		}

		if cat == 0 {
			err = n.SetCategory(1)
			if err != nil {
				return false, fmt.Errorf("SetCategory: %v", err)
			}
		} else {
			log.Printf("setFirewall: already category %v", cat)
		}

		return true, nil
	}

	return false, nil
}

func configureInterface(cfg *Config, tun *tun.NativeTun) error {
	const mtu = 0
	guid := tun.GUID()
	log.Printf("wintun GUID is %v", guid)
	iface, err := interfaceFromGUID(&guid)
	if err != nil {
		return err
	}

	go func() {
		// It takes a weirdly long time for Windows to notice the
		// new interface has come up. Poll periodically until it
		// does.
		for i := 0; i < 20; i++ {
			found, err := setFirewall(&guid)
			if err != nil {
				log.Printf("setFirewall: %v", err)
				// fall through anyway, this isn't fatal.
			}
			if found {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}()

	routes := []winipcfg.RouteData{}
	var firstGateway4 *net.IP
	var firstGateway6 *net.IP
	addresses := make([]*net.IPNet, len(cfg.LocalAddrs))
	for i, addr := range cfg.LocalAddrs {
		ipnet := addr.IPNet()
		addresses[i] = ipnet
		gateway := ipnet.IP
		if addr.IP.Is4() && firstGateway4 == nil {
			firstGateway4 = &gateway
		} else if addr.IP.Is6() && firstGateway6 == nil {
			firstGateway6 = &gateway
		}
	}

	foundDefault4 := false
	foundDefault6 := false
	for _, route := range cfg.Routes {
		if (route.IP.Is4() && firstGateway4 == nil) || (route.IP.Is6() && firstGateway6 == nil) {
			return errors.New("Due to a Windows limitation, one cannot have interface routes without an interface address")
		}

		ipn := route.IPNet()
		var gateway net.IP
		if route.IP.Is4() {
			gateway = *firstGateway4
		} else if route.IP.Is6() {
			gateway = *firstGateway6
		}
		r := winipcfg.RouteData{
			Destination: net.IPNet{
				IP:   ipn.IP.Mask(ipn.Mask),
				Mask: ipn.Mask,
			},
			NextHop: gateway,
			Metric:  0,
		}
		if bytes.Compare(r.Destination.IP, gateway) == 0 {
			// no need to add a route for the interface's
			// own IP. The kernel does that for us.
			// If we try to replace it, we'll fail to
			// add the route unless NextHop is set, but
			// then the interface's IP won't be pingable.
			continue
		}
		if route.IP.Is4() {
			if route.Bits == 0 {
				foundDefault4 = true
			}
			r.NextHop = *firstGateway4
		} else if route.IP.Is6() {
			if route.Bits == 0 {
				foundDefault6 = true
			}
			r.NextHop = *firstGateway6
		}
		routes = append(routes, r)
	}

	err = syncAddresses(iface, addresses)
	if err != nil {
		return err
	}

	sort.Slice(routes, func(i, j int) bool { return routeLess(&routes[i], &routes[j]) })

	deduplicatedRoutes := []*winipcfg.RouteData{}
	for i := 0; i < len(routes); i++ {
		// There's only one way to get to a given IP+Mask, so delete
		// all matches after the first.
		if i > 0 &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}
	log.Printf("routes: %v", routes)

	var errAcc error
	err = syncRoutes(iface, deduplicatedRoutes)
	if err != nil && errAcc == nil {
		log.Printf("setroutes: %v", err)
		errAcc = err
	}

	ipif, err := iface.LUID.IPInterface(windows.AF_INET)
	if err != nil {
		log.Printf("getipif: %v", err)
		return err
	}
	log.Printf("foundDefault4: %v", foundDefault4)
	if foundDefault4 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	if mtu > 0 {
		ipif.NLMTU = uint32(mtu)
		tun.ForceMTU(int(ipif.NLMTU))
	}
	err = ipif.Set()
	if err != nil && errAcc == nil {
		errAcc = err
	}

	ipif, err = iface.LUID.IPInterface(windows.AF_INET6)
	if err != nil {
		if !isMissingIPv6Err(err) {
			return err
		}
	} else {
		if foundDefault6 {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		}
		if mtu > 0 {
			ipif.NLMTU = uint32(mtu)
		}
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		err = ipif.Set()
		if err != nil && errAcc == nil {
			errAcc = err
		}
	}

	return errAcc
}

// isMissingIPv6Err reports whether err is due to IPv6 not being enabled on the machine.
//
// It's intended for use on errors returned by the winipcfg.Interface.GetIpInterface
// method, which ultimately calls:
// https://docs.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfaceentry
func isMissingIPv6Err(err error) bool {
	// ERROR_NOT_FOUND from means the address family (IPv6) is not found.
	// (ERROR_FILE_NOT_FOUND means that the interface doesn't exist.)
	return errors.Is(err, windows.ERROR_NOT_FOUND)
}

// routeLess reports whether ri should sort before rj.
// The actual sort order doesn't appear to matter. The caller just
// wants them sorted to be able to de-dup.
func routeLess(ri, rj *winipcfg.RouteData) bool {
	if v := bytes.Compare(ri.Destination.IP, rj.Destination.IP); v != 0 {
		return v == -1
	}
	if v := bytes.Compare(ri.Destination.Mask, rj.Destination.Mask); v != 0 {
		// Narrower masks first
		return v == 1
	}
	if ri.Metric != rj.Metric {
		// Lower metrics first
		return ri.Metric < rj.Metric
	}
	if v := bytes.Compare(ri.NextHop, rj.NextHop); v != 0 {
		// No nexthop before non-empty nexthop.
		return v == -1
	}
	return false
}
