//go:build linux

package faketcp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const rawIPv4PollQuantum = 50 * time.Millisecond

// LinuxRawIPv4Writer uses an IPPROTO_RAW socket, which is send-only on Linux,
// with IP_HDRINCL. A single locked socket makes per-write SO_MARK changes
// atomic with sendmsg; IP_PKTINFO binds the exact underlay ifindex and source.
type LinuxRawIPv4Writer struct {
	mu sync.Mutex

	fd          int
	sendTimeout time.Duration
	closeFD     func(int) error
	owned       bool
	closed      bool
	closeErr    error
}

var _ RawIPv4Writer = (*LinuxRawIPv4Writer)(nil)

func NewLinuxRawIPv4Writer(sendTimeout time.Duration) (*LinuxRawIPv4Writer, error) {
	return newLinuxRawIPv4Writer(sendTimeout, linuxRawSocketOps{
		socket: unix.Socket, setHeaderIncluded: func(fd int) error {
			return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
		}, close: unix.Close,
	})
}

type linuxRawSocketOps struct {
	socket            func(int, int, int) (int, error)
	setHeaderIncluded func(int) error
	close             func(int) error
}

func newLinuxRawIPv4Writer(
	sendTimeout time.Duration,
	ops linuxRawSocketOps,
) (*LinuxRawIPv4Writer, error) {
	if sendTimeout <= 0 {
		return nil, errors.New("faketcp raw IPv4 send timeout must be positive")
	}
	if ops.socket == nil || ops.setHeaderIncluded == nil || ops.close == nil {
		return nil, errors.New("faketcp raw IPv4 socket operations are incomplete")
	}
	fd, err := ops.socket(
		unix.AF_INET,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		unix.IPPROTO_RAW,
	)
	if err != nil {
		return nil, fmt.Errorf("open send-only faketcp raw IPv4 socket: %w", err)
	}
	if fd < 0 {
		return nil, fmt.Errorf("open send-only faketcp raw IPv4 socket returned invalid fd %d", fd)
	}
	if err := ops.setHeaderIncluded(fd); err != nil {
		closeErr := ops.close(fd)
		return nil, errors.Join(
			fmt.Errorf("enable IP_HDRINCL on faketcp raw IPv4 socket: %w", err),
			wrapRawSocketCloseError(closeErr),
		)
	}
	return &LinuxRawIPv4Writer{
		fd: fd, sendTimeout: sendTimeout, closeFD: ops.close, owned: true,
	}, nil
}

func (writer *LinuxRawIPv4Writer) WriteIPv4(ctx context.Context, write RawIPv4Write) error {
	if writer == nil {
		return ErrRawBackendClosed
	}
	if ctx == nil {
		return errors.New("write raw faketcp IPv4 packet: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if !writer.initializedLocked() || writer.closed {
		return ErrRawBackendClosed
	}
	if err := validateRawIPv4Write(write); err != nil {
		return err
	}
	sendCtx, cancel := context.WithTimeout(ctx, writer.sendTimeout)
	defer cancel()
	if err := sendCtx.Err(); err != nil {
		return err
	}
	// The kernel option is a u32. int32 preserves all mark bits on both 32-
	// and 64-bit Go targets before SetsockoptInt copies the native int value.
	if err := unix.SetsockoptInt(writer.fd, unix.SOL_SOCKET, unix.SO_MARK, int(int32(write.FWMark))); err != nil {
		return fmt.Errorf("set faketcp raw socket mark %#x: %w", write.FWMark, err)
	}
	packetInfo := unix.Inet4Pktinfo{Ifindex: int32(write.UnderlayIndex)}
	copy(packetInfo.Spec_dst[:], write.Data[12:16])
	oob := unix.PktInfo4(&packetInfo)
	destination := &unix.SockaddrInet4{}
	copy(destination.Addr[:], write.Data[16:20])

	for {
		if err := sendCtx.Err(); err != nil {
			return err
		}
		written, err := unix.SendmsgN(
			writer.fd,
			write.Data,
			oob,
			destination,
			unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL,
		)
		switch {
		case err == nil && written == len(write.Data):
			return nil
		case err == nil:
			return fmt.Errorf("raw faketcp IPv4 write was partial: %d of %d bytes", written, len(write.Data))
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EWOULDBLOCK):
			if err := pollRawIPv4Writable(sendCtx, writer.fd); err != nil {
				return err
			}
		default:
			return fmt.Errorf("send raw faketcp IPv4 packet: %w", err)
		}
	}
}

func pollRawIPv4Writable(ctx context.Context, fd int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		wait := rawIPv4PollQuantum
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return context.DeadlineExceeded
			}
			if remaining < wait {
				wait = remaining
			}
		}
		milliseconds := int(math.Ceil(float64(wait) / float64(time.Millisecond)))
		if milliseconds < 1 {
			milliseconds = 1
		}
		pollFD := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		count, err := unix.Poll(pollFD, milliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll faketcp raw IPv4 socket: %w", err)
		}
		if count == 0 {
			continue
		}
		revents := pollFD[0].Revents
		if revents&unix.POLLOUT != 0 {
			return nil
		}
		if revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return fmt.Errorf("poll faketcp raw IPv4 socket returned events %#x", revents)
		}
	}
}

func (writer *LinuxRawIPv4Writer) Close() error {
	if writer == nil {
		return nil
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if !writer.owned {
		// fd is zero in a Go zero value, but it is not owned. In contrast, a
		// successful constructor may legitimately own fd 0.
		return nil
	}
	if writer.closed {
		return writer.closeErr
	}
	writer.closed = true
	fd := writer.fd
	writer.fd = -1
	if fd >= 0 && writer.closeFD != nil {
		writer.closeErr = wrapRawSocketCloseError(writer.closeFD(fd))
	}
	return writer.closeErr
}

func (writer *LinuxRawIPv4Writer) rawIPv4WriterReady() error {
	if writer == nil {
		return ErrRawBackendClosed
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if !writer.initializedLocked() || writer.closed {
		return ErrRawBackendClosed
	}
	return nil
}

func (writer *LinuxRawIPv4Writer) initializedLocked() bool {
	return writer.owned && writer.fd >= 0 && writer.sendTimeout > 0 && writer.closeFD != nil
}

func wrapRawSocketCloseError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close faketcp raw IPv4 socket: %w", err)
}
