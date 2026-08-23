//go:build !linux

package guard

import (
	"context"
	"fmt"
)

type unsupportedNFTableLister struct{}

func newKernelNFTableLister() NFTableLister {
	return unsupportedNFTableLister{}
}

func (unsupportedNFTableLister) ListTables(ctx context.Context) ([]NFTable, error) {
	if ctx == nil {
		return nil, fmt.Errorf("list nf_tables tables: %w", ErrNFTableInventoryUnsupported)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrNFTableInventoryUnsupported
}
