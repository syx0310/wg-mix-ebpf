package packet

import (
	"encoding/binary"
	"fmt"
)

const (
	StandardInitiation    uint32 = 0x00000001
	StandardResponse      uint32 = 0x00000002
	StandardCookieReply   uint32 = 0x00000003
	StandardTransportData uint32 = 0x00000004
)

type MessageKind int

const (
	MessageUnknown MessageKind = iota
	MessageInitiation
	MessageResponse
	MessageCookieReply
	MessageTransportData
)

func (k MessageKind) String() string {
	switch k {
	case MessageInitiation:
		return "initiation"
	case MessageResponse:
		return "response"
	case MessageCookieReply:
		return "cookie_reply"
	case MessageTransportData:
		return "transport_data"
	default:
		return "unknown"
	}
}

func FromWire(b []byte) (uint32, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("type_word requires 4 bytes, got %d", len(b))
	}
	return binary.LittleEndian.Uint32(b[:4]), nil
}

func ToWire(v uint32) [4]byte {
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], v)
	return out
}

func StandardKind(typeWord uint32) MessageKind {
	switch typeWord {
	case StandardInitiation:
		return MessageInitiation
	case StandardResponse:
		return MessageResponse
	case StandardCookieReply:
		return MessageCookieReply
	case StandardTransportData:
		return MessageTransportData
	default:
		return MessageUnknown
	}
}

func ValidatePayloadLength(kind MessageKind, payloadLen int) error {
	switch kind {
	case MessageInitiation:
		if payloadLen != 148 {
			return fmt.Errorf("initiation payload length %d, want 148", payloadLen)
		}
	case MessageResponse:
		if payloadLen != 92 {
			return fmt.Errorf("response payload length %d, want 92", payloadLen)
		}
	case MessageCookieReply:
		if payloadLen != 64 {
			return fmt.Errorf("cookie reply payload length %d, want 64", payloadLen)
		}
	case MessageTransportData:
		if payloadLen < 32 {
			return fmt.Errorf("transport payload length %d is below 32", payloadLen)
		}
		if (payloadLen-32)%16 != 0 {
			return fmt.Errorf("transport payload length %d is not 16-byte padded", payloadLen)
		}
	default:
		return fmt.Errorf("unknown message kind")
	}
	return nil
}

func ContainsStandardTypeWord(payload []byte) bool {
	typeWord, err := FromWire(payload)
	if err != nil {
		return false
	}
	return StandardKind(typeWord) != MessageUnknown
}
