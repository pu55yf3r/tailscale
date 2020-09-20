/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package router

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// interfaceFromGUID returns IPAdapterAddresses with specified GUID.
func interfaceFromGUID(guid *windows.GUID) (*winipcfg.IPAdapterAddresses, error) {
	luid, err := winipcfg.LUIDFromGUID(guid)
	if err != nil {
		return nil, err
	}
	addresses, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return nil, err
	}
	for _, addr := range addresses {
		if addr.LUID == luid {
			return addr, nil
		}
	}
	return nil, fmt.Errorf("interfaceFromGUID() - interface with specified LUID not found")
}

// syncAddresses incrementally sets the interface's unicast IP addresses,
// doing the minimum number of AddAddresses & DeleteAddress calls.
// This avoids the full FlushAddresses.
//
// Any IPv6 link-local addresses are not deleted.
func syncAddresses(ifc *winipcfg.IPAdapterAddresses, want []*net.IPNet) error {
	// TODO: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	return errors.New("Not implemented")
}

// syncRoutes incrementally sets multiples routes on an interface.
// This avoids the full FlushRoutes().
func syncRoutes(ifc *winipcfg.IPAdapterAddresses, want []*winipcfg.RouteData) error {
	// TODO: !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	return errors.New("Not implemented")
}
