package faketcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

// ValidatedControl deliberately exposes no fields. It binds a complete,
// checksum-valid IPv4/TCP close packet to the exact BPF-owned session value
// against which its sequence and acknowledgement were checked.
type ValidatedControl struct {
	flow    abi.FakeTCPSessionKey
	segment Segment
	session abi.FakeTCPSessionValue
}

// ValidateIPv4TCPControl validates the complete IPv4 and TCP checksums and
// receive-window state before producing the only credential Engine accepts
// for established RST/FIN deletion. A TCP checksum field containing zero is
// neither accepted nor rejected specially: only the full one's-complement
// checksum result is authoritative.
func ValidateIPv4TCPControl(packet []byte, flow abi.FakeTCPSessionKey, session abi.FakeTCPSessionValue) (ValidatedControl, error) {
	if session.Generation != flow.Generation || session.State != abi.FakeTCPStateEstablished {
		return ValidatedControl{}, errors.New("faketcp close validation requires the matching established BPF session")
	}
	if len(packet) < 40 || packet[0]>>4 != 4 {
		return ValidatedControl{}, errors.New("faketcp close packet is not complete IPv4/TCP")
	}
	ipHeaderLength := int(packet[0]&0x0f) * 4
	if ipHeaderLength != 20 || ipHeaderLength+20 > len(packet) {
		return ValidatedControl{}, fmt.Errorf("faketcp close IPv4 header length %d is unsupported", ipHeaderLength)
	}
	if int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return ValidatedControl{}, errors.New("faketcp close IPv4 total length is inconsistent")
	}
	if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return ValidatedControl{}, errors.New("faketcp close IPv4 fragments are unsupported")
	}
	if packet[9] != 6 {
		return ValidatedControl{}, fmt.Errorf("faketcp close IPv4 protocol %d is not TCP", packet[9])
	}
	if !checksumValid(packet[:ipHeaderLength]) {
		return ValidatedControl{}, errors.New("faketcp close IPv4 checksum is invalid")
	}
	var localAddress, remoteAddress [4]byte
	binary.NativeEndian.PutUint32(localAddress[:], flow.LocalIPv4)
	binary.NativeEndian.PutUint32(remoteAddress[:], flow.RemoteIPv4)
	if !bytes.Equal(packet[12:16], remoteAddress[:]) || !bytes.Equal(packet[16:20], localAddress[:]) {
		return ValidatedControl{}, errors.New("faketcp close IPv4 endpoints do not match the session")
	}

	tcp := packet[ipHeaderLength:]
	tcpHeaderLength := int(tcp[12]>>4) * 4
	if tcpHeaderLength < 20 || tcpHeaderLength > len(tcp) {
		return ValidatedControl{}, fmt.Errorf("faketcp close TCP header length %d is invalid", tcpHeaderLength)
	}
	if binary.BigEndian.Uint16(tcp[0:2]) != flow.RemotePort || binary.BigEndian.Uint16(tcp[2:4]) != flow.LocalPort {
		return ValidatedControl{}, errors.New("faketcp close TCP ports do not match the session")
	}
	if !tcpChecksumValid(packet[12:20], tcp) {
		return ValidatedControl{}, errors.New("faketcp close TCP checksum is invalid")
	}
	flags := tcp[13]
	closeFlags := flags & (FlagRST | FlagFIN)
	if (closeFlags != FlagRST && closeFlags != FlagFIN) || flags&FlagSYN != 0 || len(tcp) != tcpHeaderLength {
		return ValidatedControl{}, errors.New("faketcp close must be a payload-free RST or FIN without SYN")
	}
	if flags&FlagFIN != 0 && flags&FlagACK == 0 {
		return ValidatedControl{}, errors.New("faketcp FIN close must acknowledge the current send window")
	}
	sequence := binary.BigEndian.Uint32(tcp[4:8])
	acknowledgement := binary.BigEndian.Uint32(tcp[8:12])
	if closeFlags == FlagRST {
		// A reset is destructive, so apply the RFC 5961 exact-next-sequence
		// rule rather than accepting any guess within a 64K receive window.
		// This prototype drops non-exact resets; a future implementation may
		// add a challenge ACK without weakening deletion authority.
		if sequence != session.RXSequence {
			return ValidatedControl{}, errors.New("faketcp RST sequence does not exactly match the BPF receive sequence")
		}
		if flags&FlagACK != 0 && acknowledgement != session.TXSequence {
			return ValidatedControl{}, errors.New("faketcp RST acknowledgement does not exactly match the BPF send sequence")
		}
	} else {
		if !sequenceInReceiveWindow(sequence, session.RXSequence, session.Window) {
			return ValidatedControl{}, errors.New("faketcp FIN sequence is outside the BPF receive window")
		}
		if !acknowledgementInSendWindow(acknowledgement, session.LocalISN+1, session.TXSequence) {
			return ValidatedControl{}, errors.New("faketcp FIN acknowledgement is outside the BPF send window")
		}
	}
	segment := Segment{Flags: flags, Sequence: sequence, Acknowledgement: acknowledgement}
	return ValidatedControl{flow: flow, segment: segment, session: session}, nil
}

func sequenceInReceiveWindow(sequence, next uint32, window uint16) bool {
	if window == 0 {
		return sequence == next
	}
	return uint32(sequence-next) < uint32(window)
}

func acknowledgementInSendWindow(acknowledgement, first, next uint32) bool {
	return !sequenceBefore(acknowledgement, first) && !sequenceBefore(next, acknowledgement)
}

func sequenceBefore(left, right uint32) bool {
	return int32(left-right) < 0
}

func tcpChecksumValid(addresses, tcp []byte) bool {
	return transportChecksumValid(addresses, 6, tcp)
}
