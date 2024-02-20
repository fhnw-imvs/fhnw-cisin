package ifacesrepository

import (
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	"net"
	"strings"
)

type ifacesNet struct {
	ipAddresses []string
}

func NewIfacesNet() (Ifaces, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	ipAddresses := make([]string, 0)

	for _, iface := range ifaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
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
		return "", err
	}

	if len(names) > 0 {
		return names[0], nil
	}

	return "", constant.ErrNotFound
}
