//go:build linux

package runtime

import (
	"context"
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl"
)

type SystemProvider struct{}

func NewSystemProvider() Provider {
	return SystemProvider{}
}

func (SystemProvider) Device(_ context.Context, name string) (*Device, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()

	dev, err := client.Device(name)
	if err != nil {
		return nil, err
	}
	out := &Device{
		Name:         dev.Name,
		ListenPort:   uint16(dev.ListenPort),
		FirewallMark: uint32(dev.FirewallMark),
		Up:           true,
	}
	if iface, err := net.InterfaceByName(dev.Name); err == nil {
		out.IfIndex = iface.Index
	}
	for _, peer := range dev.Peers {
		p := Peer{
			PublicKey:         peer.PublicKey.String(),
			ReceiveBytes:      peer.ReceiveBytes,
			TransmitBytes:     peer.TransmitBytes,
			LastHandshakeUnix: peer.LastHandshakeTime.Unix(),
		}
		if peer.Endpoint != nil {
			p.Endpoint = peer.Endpoint.String()
		}
		if peer.PersistentKeepaliveInterval != 0 {
			p.PersistentKeepalive = int64(peer.PersistentKeepaliveInterval.Seconds())
		}
		out.Peers = append(out.Peers, p)
	}
	if out.ListenPort == 0 {
		return nil, fmt.Errorf("wireguard runtime device %s has zero ListenPort", name)
	}
	return out, nil
}
