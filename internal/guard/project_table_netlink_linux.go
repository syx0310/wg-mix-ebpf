//go:build linux

package guard

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const defaultNFTableInventoryTimeout = 5 * time.Second

func newKernelNFTableLister() NFTableLister {
	return netlinkNFTableLister{query: queryKernelNFTables}
}

func queryKernelNFTables(ctx context.Context, request netlink.Message) ([]netlink.Message, error) {
	if ctx == nil {
		return nil, errors.New("query kernel nf_tables: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, defaultNFTableInventoryTimeout)
	defer cancel()

	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{Strict: true})
	if err != nil {
		return nil, fmt.Errorf("open NETLINK_NETFILTER socket: %w", err)
	}
	stopCancelClose := context.AfterFunc(queryCtx, func() {
		_ = conn.Close()
	})
	messages, queryErr := conn.Execute(request)
	stopped := stopCancelClose()
	closeErr := conn.Close()

	if err := queryCtx.Err(); err != nil {
		return nil, err
	}
	if queryErr != nil {
		return nil, errors.Join(queryErr, closeErr)
	}
	// If cancellation won the race, ctx.Err above is authoritative and the
	// close may already have happened. Otherwise a close failure is a real
	// resource-management error and the preflight remains fail-closed.
	if stopped && closeErr != nil {
		return nil, fmt.Errorf("close NETLINK_NETFILTER socket: %w", closeErr)
	}
	return messages, nil
}
