//go:build linux

package faketcp

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestLinuxRawIPv4WriterOwnsAndClosesFDZero(t *testing.T) {
	var closed []int
	writer, err := newLinuxRawIPv4Writer(time.Second, linuxRawSocketOps{
		socket: func(int, int, int) (int, error) { return 0, nil },
		setHeaderIncluded: func(fd int) error {
			if fd != 0 {
				t.Fatalf("IP_HDRINCL fd=%d, want 0", fd)
			}
			return nil
		},
		close: func(fd int) error {
			closed = append(closed, fd)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !writer.owned || writer.fd != 0 {
		t.Fatalf("constructed writer owned=%t fd=%d", writer.owned, writer.fd)
	}
	if err := writer.rawIPv4WriterReady(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(closed, []int{0}) {
		t.Fatalf("closed fds=%v", closed)
	}
}

func TestLinuxRawIPv4WriterCloseErrorConsumesFDWithoutNumericRetry(t *testing.T) {
	wantErr := errors.New("close failed after consuming fd")
	var closed []int
	writer, err := newLinuxRawIPv4Writer(time.Second, linuxRawSocketOps{
		socket:            func(int, int, int) (int, error) { return 17, nil },
		setHeaderIncluded: func(int) error { return nil },
		close: func(fd int) error {
			closed = append(closed, fd)
			return wantErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("first Close error=%v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("terminal Close retry error=%v", err)
	}
	if !slices.Equal(closed, []int{17}) {
		t.Fatalf("closed fds=%v", closed)
	}
}

func TestLinuxRawIPv4WriterZeroValueFailsClosedWithoutClosingFDZero(t *testing.T) {
	writer := &LinuxRawIPv4Writer{}
	if err := writer.Close(); err != nil {
		t.Fatalf("zero-value Close error=%v", err)
	}
	flow := testFlow(31001)
	if err := writer.WriteIPv4(context.Background(), RawIPv4Write{
		Data: testPendingPacket(t, flow, 1).Data, UnderlayIndex: flow.UnderlayIndex,
	}); !errors.Is(err, ErrRawBackendClosed) {
		t.Fatalf("zero-value WriteIPv4 error=%v", err)
	}
	resolver := ControlMarkResolverFunc(func(context.Context, abi.FakeTCPSessionKey, uint32) (uint32, error) {
		return 1, nil
	})
	if backend, err := NewRawControllerBackend(RawControllerBackendOptions{
		Writer: writer, ControlMarks: resolver, MaxRememberedReinjections: 1,
	}); err == nil || backend != nil || !errors.Is(err, ErrRawBackendClosed) {
		t.Fatalf("zero-value writer accepted: backend=%#v err=%v", backend, err)
	}
}

func TestLinuxRawIPv4WriterConstructorFailureClosesFDZero(t *testing.T) {
	wantErr := errors.New("IP_HDRINCL failed")
	var closed []int
	writer, err := newLinuxRawIPv4Writer(time.Second, linuxRawSocketOps{
		socket:            func(int, int, int) (int, error) { return 0, nil },
		setHeaderIncluded: func(int) error { return wantErr },
		close: func(fd int) error {
			closed = append(closed, fd)
			return nil
		},
	})
	if writer != nil || !errors.Is(err, wantErr) {
		t.Fatalf("writer=%#v err=%v", writer, err)
	}
	if !slices.Equal(closed, []int{0}) {
		t.Fatalf("closed fds=%v", closed)
	}
}
