package netnsanchor

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testContract() contract {
	return contract{
		RunID: "0123abcd",
		Role:  "a",
		Token: strings.Repeat("a", 64),
		Identity: Identity{
			Device: 42,
			Inode:  99,
		},
		Deadline: time.Now().Add(time.Minute),
	}
}

func TestValidateRequestBindsIdentityActionAndToken(t *testing.T) {
	expected := testContract()
	base := request{
		Version: protocolVersion,
		Action:  "exec",
		RunID:   expected.RunID,
		Role:    expected.Role,
		Token:   expected.Token,
	}
	if err := validateRequest(base, expected); err != nil {
		t.Fatalf("valid request was rejected: %v", err)
	}
	createVeth := base
	createVeth.Action = "create-veth-pair"
	if err := validateRequest(createVeth, expected); err != nil {
		t.Fatalf("atomic veth request was rejected: %v", err)
	}
	legacyMove := base
	legacyMove.Action = "move-link"
	if err := validateRequest(legacyMove, expected); err == nil {
		t.Fatal("legacy host-link move action was accepted")
	}

	tests := []struct {
		name   string
		mutate func(*request)
	}{
		{"version", func(value *request) { value.Version++ }},
		{"action", func(value *request) { value.Action = "unknown" }},
		{"run", func(value *request) { value.RunID = "ffffffff" }},
		{"role", func(value *request) { value.Role = "b" }},
		{"token", func(value *request) { value.Token = strings.Repeat("b", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.mutate(&value)
			if err := validateRequest(value, expected); err == nil {
				t.Fatal("mismatched request was accepted")
			}
		})
	}

	expired := expected
	expired.Deadline = time.Now().Add(-time.Second)
	if err := validateRequest(base, expired); err == nil {
		t.Fatal("expired anchor contract was accepted")
	}
}

func TestVerifyIdentity(t *testing.T) {
	expected := Identity{Device: 7, Inode: 11}
	if err := verifyIdentity(expected, expected); err != nil {
		t.Fatalf("matching identity was rejected: %v", err)
	}
	if err := verifyIdentity(Identity{Device: 7, Inode: 12}, expected); err == nil {
		t.Fatal("changed inode was accepted")
	}
	if err := verifyIdentity(expected, Identity{}); err == nil {
		t.Fatal("unsealed expected identity was accepted")
	}
}

func TestStopStateRejectsRepeatedStop(t *testing.T) {
	var state stopState
	if err := state.stop(); err != nil {
		t.Fatalf("first stop failed: %v", err)
	}
	if !state.isStopped() {
		t.Fatal("stop state did not transition")
	}
	if err := state.stop(); err == nil {
		t.Fatal("repeated stop was accepted")
	}
}

func TestProtocolTransfersExactlyOneDescriptor(t *testing.T) {
	left, right := unixConnectionPair(t)
	defer left.Close()
	defer right.Close()

	source, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open harmless descriptor: %v", err)
	}
	defer source.Close()

	sendErr := make(chan error, 1)
	go func() {
		sendErr <- sendResponse(left, response{
			Version: protocolVersion,
			OK:      true,
			Device:  42,
			Inode:   99,
		}, int(source.Fd()))
	}()
	got, descriptor, err := receiveResponse(right, true)
	if err != nil {
		t.Fatalf("receive response: %v", err)
	}
	defer unix.Close(descriptor)
	if err := <-sendErr; err != nil {
		t.Fatalf("send response: %v", err)
	}
	if got.Device != 42 || got.Inode != 99 {
		t.Fatalf("unexpected identity: %+v", got)
	}
	if _, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0); err != nil {
		t.Fatalf("received descriptor is invalid: %v", err)
	}
}

func TestProtocolRejectsMissingAndUnexpectedDescriptors(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		left, right := unixConnectionPair(t)
		defer left.Close()
		defer right.Close()
		sendErr := make(chan error, 1)
		go func() {
			sendErr <- sendResponse(
				left,
				response{Version: protocolVersion, OK: true},
				-1,
			)
		}()
		if _, _, err := receiveResponse(right, true); err == nil {
			t.Fatal("missing descriptor was accepted")
		}
		if err := <-sendErr; err != nil {
			t.Fatalf("send missing-descriptor response: %v", err)
		}
	})

	t.Run("unexpected", func(t *testing.T) {
		left, right := unixConnectionPair(t)
		defer left.Close()
		defer right.Close()
		source, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatalf("open harmless descriptor: %v", err)
		}
		defer source.Close()
		sourceFD := int(source.Fd())
		sendErr := make(chan error, 1)
		go func() {
			sendErr <- sendResponse(
				left,
				response{Version: protocolVersion, OK: true},
				sourceFD,
			)
		}()
		if _, _, err := receiveResponse(right, false); err == nil {
			t.Fatal("unexpected descriptor was accepted")
		}
		if err := <-sendErr; err != nil {
			t.Fatalf("send unexpected-descriptor response: %v", err)
		}
	})
}

func TestProtocolRejectsMalformedOrDescriptorBearingRequest(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		left, right := unixConnectionPair(t)
		defer left.Close()
		defer right.Close()
		sendErr := make(chan error, 1)
		go func() {
			_, _, err := left.WriteMsgUnix(
				[]byte(`{"version":1,"extra":true}`),
				nil,
				nil,
			)
			sendErr <- err
		}()
		if _, err := receiveRequest(right); err == nil {
			t.Fatal("unknown protocol field was accepted")
		}
		if err := <-sendErr; err != nil {
			t.Fatalf("send malformed request: %v", err)
		}
	})

	t.Run("descriptor", func(t *testing.T) {
		left, right := unixConnectionPair(t)
		defer left.Close()
		defer right.Close()
		source, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatalf("open harmless descriptor: %v", err)
		}
		defer source.Close()
		sourceFD := int(source.Fd())
		value := request{
			Version: protocolVersion,
			Action:  "probe",
			RunID:   "0123abcd",
			Role:    "a",
			Token:   strings.Repeat("a", 64),
		}
		sendErr := make(chan error, 1)
		go func() {
			sendErr <- writePacket(left, value, sourceFD)
		}()
		if _, err := receiveRequest(right); err == nil {
			t.Fatal("descriptor-bearing request was accepted")
		}
		if err := <-sendErr; err != nil {
			t.Fatalf("send descriptor-bearing request: %v", err)
		}
	})
}

func TestProtocolReadDeadlineIsBounded(t *testing.T) {
	left, right := unixConnectionPair(t)
	defer left.Close()
	defer right.Close()
	if err := right.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, err := receiveRequest(right)
	if err == nil {
		t.Fatal("silent peer did not time out")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("timeout error was not preserved: %v", err)
	}
}

func unixConnectionPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	descriptors, err := unix.Socketpair(
		unix.AF_UNIX,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		t.Fatalf("create unixpacket socketpair: %v", err)
	}
	unix.CloseOnExec(descriptors[0])
	unix.CloseOnExec(descriptors[1])
	files := []*os.File{
		os.NewFile(uintptr(descriptors[0]), "left"),
		os.NewFile(uintptr(descriptors[1]), "right"),
	}
	connections := make([]*net.UnixConn, 0, 2)
	for _, file := range files {
		connection, fileErr := net.FileConn(file)
		_ = file.Close()
		if fileErr != nil {
			for _, existing := range connections {
				_ = existing.Close()
			}
			t.Fatalf("wrap socketpair endpoint: %v", fileErr)
		}
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok {
			_ = connection.Close()
			t.Fatalf("socketpair endpoint has type %T", connection)
		}
		connections = append(connections, unixConnection)
	}
	return connections[0], connections[1]
}
