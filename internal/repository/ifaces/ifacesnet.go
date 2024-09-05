// Copyright (c) 2024 Esra Siegert
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package ifacesrepository

import (
	"fmt"
	"net"
	"strings"

	"github.com/fhnw-imvs/fhnw-cisin/internal/constant"
)

type ifacesNet struct {
	ipAddresses []string
}

// NewIfacesNet represents a net based implementation of Ifaces.
func NewIfacesNet() (Ifaces, error) {
	// get host interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	ipAddresses := make([]string, 0)

	// get ip addresses from interfaces
	for _, iface := range ifaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list interface addresses: %w", err)
		}

		for _, addr := range addresses {
			ipAddresses = append(ipAddresses, strings.Split(addr.String(), "/")[0])
		}
	}

	return ifacesNet{
		ipAddresses: ipAddresses,
	}, nil
}

func (i ifacesNet) GetIPAddresses() ([]string, error) {
	return i.ipAddresses, nil
}

func (i ifacesNet) LookupAddr(ip string) (string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return "", fmt.Errorf("lookup ip %s: %w", ip, err)
	}

	if len(names) > 0 {
		return names[0], nil
	}

	return "", constant.ErrNotFound
}
