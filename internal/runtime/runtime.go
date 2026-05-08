package runtime

import (
	"context"
	"errors"
)

var ErrUnsupported = errors.New("runtime provider is unsupported on this platform")

type Device struct {
	Name         string
	IfIndex      int
	Up           bool
	ListenPort   uint16
	FirewallMark uint32
	Peers        []Peer
}

type Peer struct {
	PublicKey           string
	Endpoint            string
	LastHandshakeUnix   int64
	ReceiveBytes        int64
	TransmitBytes       int64
	PersistentKeepalive int64
}

type Provider interface {
	Device(ctx context.Context, name string) (*Device, error)
}

type StaticProvider struct {
	Devices map[string]*Device
}

func (p StaticProvider) Device(_ context.Context, name string) (*Device, error) {
	if p.Devices == nil {
		return nil, ErrUnsupported
	}
	dev, ok := p.Devices[name]
	if !ok {
		return nil, ErrNotFound(name)
	}
	copied := *dev
	if dev.Peers != nil {
		copied.Peers = append([]Peer(nil), dev.Peers...)
	}
	return &copied, nil
}

type ErrNotFound string

func (e ErrNotFound) Error() string {
	return "wireguard runtime device not found: " + string(e)
}
