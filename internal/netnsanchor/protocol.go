package netnsanchor

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	protocolVersion = 1
	maxPacketSize   = 4096
	maxDescriptors  = 253
)

var (
	runIDPattern = regexp.MustCompile(`^[0-9a-f]{8}$`)
	rolePattern  = regexp.MustCompile(`^[arb]$`)
)

// Identity is the immutable kernel identity of an anonymous network namespace.
type Identity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type request struct {
	Version int    `json:"version"`
	Action  string `json:"action"`
	RunID   string `json:"run_id"`
	Role    string `json:"role"`
	Token   string `json:"token"`
}

type response struct {
	Version  int    `json:"version"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Device   uint64 `json:"device,omitempty"`
	Inode    uint64 `json:"inode,omitempty"`
	Deadline int64  `json:"deadline_unix,omitempty"`
}

type contract struct {
	RunID    string
	Role     string
	Token    string
	Identity Identity
	Deadline time.Time
}

func (c contract) validate() error {
	if !runIDPattern.MatchString(c.RunID) {
		return fmt.Errorf("invalid run ID %q", c.RunID)
	}
	if !rolePattern.MatchString(c.Role) {
		return fmt.Errorf("invalid role %q", c.Role)
	}
	if len(c.Token) != 64 {
		return errors.New("authentication token must contain 64 hexadecimal characters")
	}
	for _, character := range c.Token {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return errors.New("authentication token must be lowercase hexadecimal")
		}
	}
	if c.Identity.Device == 0 || c.Identity.Inode == 0 {
		return errors.New("network namespace identity is unsealed")
	}
	if c.Deadline.IsZero() {
		return errors.New("anchor deadline is unset")
	}
	return nil
}

func validateRequest(got request, expected contract) error {
	if err := expected.validate(); err != nil {
		return fmt.Errorf("invalid anchor contract: %w", err)
	}
	if got.Version != protocolVersion {
		return fmt.Errorf("unsupported protocol version %d", got.Version)
	}
	switch got.Action {
	case "probe", "exec", "create-veth-pair", "stop":
	default:
		return fmt.Errorf("unsupported action %q", got.Action)
	}
	if got.RunID != expected.RunID || got.Role != expected.Role {
		return errors.New("request identity does not match anchor contract")
	}
	if len(got.Token) != len(expected.Token) ||
		subtle.ConstantTimeCompare([]byte(got.Token), []byte(expected.Token)) != 1 {
		return errors.New("request authentication failed")
	}
	if !time.Now().Before(expected.Deadline) {
		return errors.New("anchor contract has expired")
	}
	return nil
}

func verifyIdentity(got, expected Identity) error {
	if expected.Device == 0 || expected.Inode == 0 {
		return errors.New("expected network namespace identity is unsealed")
	}
	if got != expected {
		return fmt.Errorf(
			"network namespace identity mismatch: expected=%d:%d observed=%d:%d",
			expected.Device,
			expected.Inode,
			got.Device,
			got.Inode,
		)
	}
	return nil
}

type stopState struct {
	mu      sync.Mutex
	stopped bool
}

func (s *stopState) stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errors.New("anchor is already stopped")
	}
	s.stopped = true
	return nil
}

func (s *stopState) isStopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

func encodePacket(value any) ([]byte, error) {
	packet, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode protocol packet: %w", err)
	}
	if len(packet) == 0 || len(packet) > maxPacketSize {
		return nil, fmt.Errorf("protocol packet size %d is invalid", len(packet))
	}
	return packet, nil
}

func decodePacket(packet []byte, value any) error {
	if len(packet) == 0 || len(packet) > maxPacketSize {
		return fmt.Errorf("protocol packet size %d is invalid", len(packet))
	}
	decoder := json.NewDecoder(newByteReader(packet))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode protocol packet: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("protocol packet contains a second JSON value")
		}
		return fmt.Errorf("decode protocol packet trailer: %w", err)
	}
	return nil
}

// byteReader is deliberately tiny so protocol parsing does not accept another
// framing layer around a unixpacket message.
type byteReader struct {
	value  []byte
	offset int
}

func newByteReader(value []byte) *byteReader {
	return &byteReader{value: value}
}

func (r *byteReader) Read(destination []byte) (int, error) {
	if r.offset == len(r.value) {
		return 0, io.EOF
	}
	count := copy(destination, r.value[r.offset:])
	r.offset += count
	return count, nil
}

func writePacket(connection *net.UnixConn, value any, fd int) error {
	packet, err := encodePacket(value)
	if err != nil {
		return err
	}
	var control []byte
	if fd >= 0 {
		control = unix.UnixRights(fd)
	}
	written, controlWritten, err := connection.WriteMsgUnix(packet, control, nil)
	if err != nil {
		return fmt.Errorf("write protocol packet: %w", err)
	}
	if written != len(packet) || controlWritten != len(control) {
		return fmt.Errorf(
			"short protocol write: payload=%d/%d control=%d/%d",
			written,
			len(packet),
			controlWritten,
			len(control),
		)
	}
	return nil
}

func readPacket(connection *net.UnixConn) ([]byte, []int, error) {
	packet := make([]byte, maxPacketSize+1)
	control := make([]byte, unix.CmsgSpace(maxDescriptors*4))
	count, controlCount, flags, _, err := connection.ReadMsgUnix(packet, control)
	if err != nil {
		return nil, nil, fmt.Errorf("read protocol packet: %w", err)
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlCount])
	if err != nil {
		return nil, nil, fmt.Errorf("parse protocol control message: %w", err)
	}
	var descriptors []int
	for _, message := range messages {
		rights, rightsErr := unix.ParseUnixRights(&message)
		if rightsErr != nil {
			closeDescriptors(descriptors)
			return nil, nil, fmt.Errorf("parse descriptor rights: %w", rightsErr)
		}
		for _, descriptor := range rights {
			unix.CloseOnExec(descriptor)
			descriptors = append(descriptors, descriptor)
		}
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || count > maxPacketSize {
		closeDescriptors(descriptors)
		return nil, nil, errors.New("truncated or oversized protocol packet")
	}
	return packet[:count], descriptors, nil
}

func closeDescriptors(descriptors []int) {
	for _, descriptor := range descriptors {
		_ = unix.Close(descriptor)
	}
}

func sendRequest(connection *net.UnixConn, value request) error {
	return writePacket(connection, value, -1)
}

func receiveRequest(connection *net.UnixConn) (request, error) {
	packet, descriptors, err := readPacket(connection)
	if err != nil {
		return request{}, err
	}
	if len(descriptors) != 0 {
		closeDescriptors(descriptors)
		return request{}, errors.New("request unexpectedly carried a descriptor")
	}
	var value request
	if err := decodePacket(packet, &value); err != nil {
		return request{}, err
	}
	return value, nil
}

func sendResponse(connection *net.UnixConn, value response, fd int) error {
	return writePacket(connection, value, fd)
}

func receiveResponse(connection *net.UnixConn, wantDescriptor bool) (response, int, error) {
	packet, descriptors, err := readPacket(connection)
	if err != nil {
		return response{}, -1, err
	}
	var value response
	if err := decodePacket(packet, &value); err != nil {
		closeDescriptors(descriptors)
		return response{}, -1, err
	}
	if value.Version != protocolVersion {
		closeDescriptors(descriptors)
		return response{}, -1, fmt.Errorf(
			"unsupported response protocol version %d",
			value.Version,
		)
	}
	if !value.OK {
		closeDescriptors(descriptors)
		if value.Error == "" {
			return response{}, -1, errors.New("anchor returned an unspecified error")
		}
		return response{}, -1, errors.New(value.Error)
	}
	if wantDescriptor {
		if len(descriptors) != 1 {
			closeDescriptors(descriptors)
			return response{}, -1, fmt.Errorf(
				"anchor returned %d descriptors, expected exactly one",
				len(descriptors),
			)
		}
		return value, descriptors[0], nil
	}
	if len(descriptors) != 0 {
		closeDescriptors(descriptors)
		return response{}, -1, errors.New("anchor unexpectedly returned a descriptor")
	}
	return value, -1, nil
}
