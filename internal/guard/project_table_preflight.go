package guard

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

const nftTableFamilyINet = "inet"

// ErrNFTableInventoryUnsupported reports that the current operating system
// cannot perform the read-only nf_tables inventory required by the explicit
// startup_guard.mode=none profile.
var ErrNFTableInventoryUnsupported = errors.New("read-only nf_tables inventory is unsupported on this platform")

// NFTable is the safety-relevant portion of one kernel nf_tables table.
// Family uses nft's stable names (for example, "inet" and "ip").
type NFTable struct {
	Family string
	Name   string
}

// NFTableLister inventories kernel nf_tables tables without changing them.
// Implementations must not queue or flush nftables mutations.
type NFTableLister interface {
	ListTables(context.Context) ([]NFTable, error)
}

// ProjectTablePreflight proves that startup_guard.mode=none will not coexist
// with a legacy, owned, or orphaned wg-mix-ebpf guard table. It is deliberately
// independent of the nft command executor so a no-nft deployment never needs
// an nft binary or subprocess.
type ProjectTablePreflight struct {
	lister NFTableLister
}

// NewProjectTablePreflight returns the platform implementation. Linux uses a
// read-only NETLINK_NETFILTER NFT_MSG_GETTABLE dump; other platforms return an
// explicit unsupported error rather than silently skipping the check.
func NewProjectTablePreflight() ProjectTablePreflight {
	return ProjectTablePreflight{lister: newKernelNFTableLister()}
}

// NewProjectTablePreflightWithLister supplies an inventory implementation.
// It is primarily useful to share a frozen inventory source with status or to
// inject deterministic kernel observations in tests.
func NewProjectTablePreflightWithLister(lister NFTableLister) ProjectTablePreflight {
	return ProjectTablePreflight{lister: lister}
}

// listProjectTables obtains and validates one complete read-only inventory,
// then returns only the inet tables reserved by this project. Keeping this
// separate from ProjectTablePreflight is important: callers which are
// resolving one owned table need the exact snapshot, not mode=none's policy
// error that rejects every project table.
func listProjectTables(ctx context.Context, lister NFTableLister) ([]string, error) {
	if ctx == nil {
		return nil, errors.New("context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lister == nil {
		return nil, errors.New("table lister is nil")
	}

	tables, err := lister.ListTables(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(tables))
	projectTables := make([]string, 0)
	for index, table := range tables {
		if table.Family == "" || table.Name == "" {
			return nil, fmt.Errorf("table %d has empty family or name", index)
		}
		identity := table.Family + "\x00" + table.Name
		if _, duplicate := seen[identity]; duplicate {
			return nil, fmt.Errorf("duplicate %s table %q", table.Family, table.Name)
		}
		seen[identity] = struct{}{}
		if table.Family == nftTableFamilyINet && isProjectTableName(table.Name) {
			projectTables = append(projectTables, table.Name)
		}
	}

	sort.Strings(projectTables)
	return projectTables, nil
}

// Check performs a fresh read-only inventory. ObservationAbsent means the
// complete inventory proved that no inet project guard table exists. Every
// inventory, validation, cancellation, or collision error returns Unknown and
// therefore fails closed before dataplane mutation.
func (p ProjectTablePreflight) Check(ctx context.Context) (Outcome, error) {
	projectTables, err := listProjectTables(ctx, p.lister)
	if err != nil {
		return unknownOutcome(), fmt.Errorf("inventory disabled startup guard: %w", err)
	}

	if len(projectTables) != 0 {
		return unknownOutcome(), fmt.Errorf(
			"inventory disabled startup guard: inet project guard tables %v exist; refusing startup_guard.mode=none",
			projectTables,
		)
	}
	return Outcome{Observation: ObservationAbsent}, nil
}
