package faketcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

// validateIPv4TCPControl validates the complete IPv4 and TCP checksums and
// exact established-state expectations. It is deliberately private: the only
// teardown authority is Engine.InboundCapturedControl, which invokes this
// validator under Engine.mu with the runtime identity from a packet-bearing
// BPF event and a fresh store snapshot. A TCP checksum field containing zero
// is neither accepted nor rejected specially; only the full one's-complement
// residual is authoritative.
func validateIPv4TCPControl(
	packet []byte,
	flow abi.FakeTCPSessionKey,
	session abi.FakeTCPSessionValue,
	identity RuntimeIdentity,
) (Segment, error) {
	if err := validateRuntimeIdentity(identity); err != nil {
		return Segment{}, fmt.Errorf("faketcp close runtime identity is invalid: %w", err)
	}
	if identity.Generation != flow.Generation {
		return Segment{}, errors.New("faketcp close runtime identity generation does not match the flow")
	}
	if err := validatePacketFlow(flow); err != nil {
		return Segment{}, fmt.Errorf("faketcp close flow is invalid: %w", err)
	}
	if err := validateEstablishedSessionValue(session, flow.Generation); err != nil {
		return Segment{}, fmt.Errorf("faketcp close validation requires the matching established BPF session: %w", err)
	}
	if session.Window == 0 {
		return Segment{}, errors.New("faketcp close validation requires a non-zero BPF session window")
	}
	if len(packet) != controlPacketLength || packet[0]>>4 != 4 {
		return Segment{}, errors.New("faketcp close packet is not complete IPv4/TCP")
	}
	ipHeaderLength := int(packet[0]&0x0f) * 4
	if ipHeaderLength != controlIPv4HeaderLength || ipHeaderLength+controlTCPHeaderLength != len(packet) {
		return Segment{}, fmt.Errorf("faketcp close IPv4 header length %d is unsupported", ipHeaderLength)
	}
	if int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return Segment{}, errors.New("faketcp close IPv4 total length is inconsistent")
	}
	if binary.BigEndian.Uint16(packet[6:8])&0xbfff != 0 {
		return Segment{}, errors.New("faketcp close reserved IPv4 flags and fragments are unsupported")
	}
	if packet[9] != 6 {
		return Segment{}, fmt.Errorf("faketcp close IPv4 protocol %d is not TCP", packet[9])
	}
	if !checksumValid(packet[:ipHeaderLength]) {
		return Segment{}, errors.New("faketcp close IPv4 checksum is invalid")
	}
	var localAddress, remoteAddress [4]byte
	binary.NativeEndian.PutUint32(localAddress[:], flow.LocalIPv4)
	binary.NativeEndian.PutUint32(remoteAddress[:], flow.RemoteIPv4)
	if !bytes.Equal(packet[12:16], remoteAddress[:]) || !bytes.Equal(packet[16:20], localAddress[:]) {
		return Segment{}, errors.New("faketcp close IPv4 endpoints do not match the session")
	}

	tcp := packet[ipHeaderLength:]
	tcpHeaderLength := int(tcp[12]>>4) * 4
	if tcpHeaderLength != controlTCPHeaderLength || tcp[12] != controlTCPHeaderLength/4<<4 {
		return Segment{}, fmt.Errorf("faketcp close TCP header length %d is invalid", tcpHeaderLength)
	}
	if binary.BigEndian.Uint16(tcp[0:2]) != flow.RemotePort || binary.BigEndian.Uint16(tcp[2:4]) != flow.LocalPort {
		return Segment{}, errors.New("faketcp close TCP ports do not match the session")
	}
	if !tcpChecksumValid(packet[12:20], tcp) {
		return Segment{}, errors.New("faketcp close TCP checksum is invalid")
	}
	flags := tcp[13]
	if flags != FlagRST|FlagACK && flags != FlagFIN|FlagACK {
		return Segment{}, errors.New("faketcp close flags must be exactly RST|ACK or FIN|ACK")
	}
	if binary.BigEndian.Uint16(tcp[18:20]) != 0 {
		return Segment{}, errors.New("faketcp close urgent pointer must be zero")
	}
	sequence := binary.BigEndian.Uint32(tcp[4:8])
	acknowledgement := binary.BigEndian.Uint32(tcp[8:12])
	if sequence != session.RXSequence {
		return Segment{}, errors.New("faketcp close sequence does not exactly match the BPF receive sequence")
	}
	if acknowledgement != session.TXSequence {
		return Segment{}, errors.New("faketcp close acknowledgement does not exactly match the BPF send sequence")
	}
	if binary.BigEndian.Uint16(tcp[14:16]) != session.Window {
		return Segment{}, errors.New("faketcp close window does not exactly match the BPF session window")
	}
	return Segment{Flags: flags, Sequence: sequence, Acknowledgement: acknowledgement}, nil
}

func tcpChecksumValid(addresses, tcp []byte) bool {
	return transportChecksumValid(addresses, 6, tcp)
}
