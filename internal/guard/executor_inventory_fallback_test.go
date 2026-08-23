package guard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailedExactInspectionUsesInventoryInsteadOfStderr(t *testing.T) {
	const target = TableName + "_0123456789abcdef0123456789abcdef"
	diagnostics := map[string]string{
		"classic": "Error: No such file or directory\nlist table inet " + target,
		"empty":   "",
		"wrapper": "distribution wrapper rejected the request before rendering nft diagnostics",
		"changed": "table lookup returned code ENOENT without echoing the request",
	}
	for name, diagnostic := range diagnostics {
		t.Run(name, func(t *testing.T) {
			inventoryCalls := 0
			executor := NewCommandExecutorWithNFTableLister(
				t.TempDir(),
				nfTableListerFunc(func(context.Context) ([]NFTable, error) {
					inventoryCalls++
					return []NFTable{
						{Family: "inet", Name: "unrelated"},
						{Family: "ip", Name: target},
					}, nil
				}),
			)
			executor.Binary = writeFailingNft(t, diagnostic)

			identity, err := executor.inspect(t.Context(), target)
			if err != nil {
				t.Fatalf("complete netlink absence should override diagnostic %q: %v", diagnostic, err)
			}
			if identity != (tableIdentity{}) {
				t.Fatalf("identity = %#v, want authoritative absence", identity)
			}
			if inventoryCalls != 1 {
				t.Fatalf("inventory calls = %d, want 1", inventoryCalls)
			}
		})
	}
}

func TestSuccessfulExactInspectionDoesNotCallFallbackInventory(t *testing.T) {
	const target = TableName + "_0123456789abcdef0123456789abcdef"
	const marker = "wg-mix-ebpf-guard-v2:test-owner"
	executor := NewCommandExecutorWithNFTableLister(
		t.TempDir(),
		nfTableListerFunc(func(context.Context) ([]NFTable, error) {
			t.Fatal("successful exact inspection called fallback netlink inventory")
			return nil, nil
		}),
	)
	executor.Binary = writeSuccessfulNftIdentity(t, target, marker)

	identity, err := executor.inspect(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	want := tableIdentity{Exists: true, Handle: 42, Comment: marker}
	if identity != want {
		t.Fatalf("identity = %#v, want %#v", identity, want)
	}
}

func TestFailedExactInspectionFailsClosedOnInventoryPresenceOrFailure(t *testing.T) {
	const target = TableName + "_0123456789abcdef0123456789abcdef"
	const orphan = TableName + "_ffffffffffffffffffffffffffffffff"
	queryErr := errors.New("netfilter inventory permission denied")
	tests := []struct {
		name         string
		lister       NFTableLister
		wantExists   bool
		wantError    string
		wantSentinel error
	}{
		{
			name: "target-present",
			lister: nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				return []NFTable{{Family: "inet", Name: target}}, nil
			}),
			wantExists: true,
			wantError:  "exact handle and ownership could not be inspected",
		},
		{
			name: "target-and-conflict-present",
			lister: nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				return []NFTable{
					{Family: "inet", Name: target},
					{Family: "inet", Name: orphan},
				}, nil
			}),
			wantExists: true,
			wantError:  "exact handle and ownership could not be inspected",
		},
		{
			name: "conflicting-project-table",
			lister: nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				return []NFTable{{Family: "inet", Name: orphan}}, nil
			}),
			wantError: "conflicting project tables",
		},
		{
			name: "malformed-inventory",
			lister: nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				return []NFTable{{Family: "inet"}}, nil
			}),
			wantError: "empty family or name",
		},
		{
			name: "duplicate-inventory",
			lister: nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				return []NFTable{
					{Family: "inet", Name: orphan},
					{Family: "inet", Name: orphan},
				}, nil
			}),
			wantError: "duplicate inet table",
		},
		{
			name: "inventory-query-error",
			lister: nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				return nil, queryErr
			}),
			wantError:    "read-only netlink inventory",
			wantSentinel: queryErr,
		},
		{
			name:      "nil-inventory",
			lister:    nil,
			wantError: "table lister is nil",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := NewCommandExecutorWithNFTableLister(t.TempDir(), test.lister)
			executor.Binary = writeFailingNft(t, "wrapper exact-list failure")

			identity, err := executor.inspect(t.Context(), target)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("inspection error = %v, want substring %q", err, test.wantError)
			}
			if identity.Exists != test.wantExists {
				t.Fatalf("identity = %#v, want Exists=%t", identity, test.wantExists)
			}
			if !strings.Contains(err.Error(), "wrapper exact-list failure") {
				t.Fatalf("hard error lost non-authoritative nft diagnostic: %v", err)
			}
			if test.wantSentinel != nil && !errors.Is(err, test.wantSentinel) {
				t.Fatalf("inspection error = %v, want errors.Is(%v)", err, test.wantSentinel)
			}
		})
	}
}

func TestFailedExactInspectionCancellationIsUnknown(t *testing.T) {
	const target = TableName + "_0123456789abcdef0123456789abcdef"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	listerCalls := 0
	executor := NewCommandExecutorWithNFTableLister(
		t.TempDir(),
		nfTableListerFunc(func(context.Context) ([]NFTable, error) {
			listerCalls++
			return nil, nil
		}),
	)
	executor.Binary = writeFailingNft(t, "unused")

	identity, err := executor.inspect(ctx, target)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled inspection error = %v, want context.Canceled", err)
	}
	if identity != (tableIdentity{}) {
		t.Fatalf("cancelled inspection identity = %#v, want unknown empty identity", identity)
	}
	if listerCalls != 0 {
		t.Fatalf("cancelled inspection called inventory %d times", listerCalls)
	}
}

func TestObserveReportsUnknownWhenFallbackCannotVerifyOwnedTable(t *testing.T) {
	const orphan = TableName + "_ffffffffffffffffffffffffffffffff"
	queryErr := errors.New("netlink protocol failure")
	tests := []struct {
		name       string
		inventory  func(owner ownerRecord) ([]NFTable, error)
		listed     func(owner ownerRecord) ([]string, error)
		want       Observation
		wantError  string
		wantTarget bool
	}{
		{
			name: "absent",
			inventory: func(ownerRecord) ([]NFTable, error) {
				return nil, nil
			},
			listed: func(ownerRecord) ([]string, error) { return nil, nil },
			want:   ObservationAbsent,
		},
		{
			name: "target-present-with-unverified-owner",
			inventory: func(owner ownerRecord) ([]NFTable, error) {
				return []NFTable{{Family: "inet", Name: owner.Table}}, nil
			},
			listed: func(owner ownerRecord) ([]string, error) {
				return []string{owner.Table}, nil
			},
			want:       ObservationUnknown,
			wantError:  "exact handle and ownership",
			wantTarget: true,
		},
		{
			name: "conflicting-project-table",
			inventory: func(ownerRecord) ([]NFTable, error) {
				return []NFTable{{Family: "inet", Name: orphan}}, nil
			},
			listed:    func(ownerRecord) ([]string, error) { return []string{orphan}, nil },
			want:      ObservationUnknown,
			wantError: "conflicting project tables",
		},
		{
			name: "malformed-inventory",
			inventory: func(ownerRecord) ([]NFTable, error) {
				return []NFTable{{Family: "inet"}}, nil
			},
			listed:    func(ownerRecord) ([]string, error) { return nil, nil },
			want:      ObservationUnknown,
			wantError: "empty family or name",
		},
		{
			name: "inventory-error",
			inventory: func(ownerRecord) ([]NFTable, error) {
				return nil, queryErr
			},
			listed:    func(ownerRecord) ([]string, error) { return nil, nil },
			want:      ObservationUnknown,
			wantError: "netlink protocol failure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateDir := guardTestStateDir(t)
			owner := seedOwnerRecord(t, stateDir)
			executor := NewCommandExecutorWithNFTableLister(
				stateDir,
				nfTableListerFunc(func(context.Context) ([]NFTable, error) {
					return test.inventory(owner)
				}),
			)
			executor.Binary = writeFailingNft(t, "opaque wrapper wording")
			executor.listTables = func(context.Context) ([]string, error) {
				return test.listed(owner)
			}

			outcome, err := executor.Observe(t.Context())
			if outcome.Observation != test.want || outcome.Mutated || outcome.Warning != nil {
				t.Fatalf("Observe outcome = %#v, want %q without mutation/warning", outcome, test.want)
			}
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Observe returned error for proved absence: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Observe error = %v, want substring %q", err, test.wantError)
			}
			if test.wantTarget && !strings.Contains(err.Error(), owner.Table) {
				t.Fatalf("target-presence error does not identify table %s: %v", owner.Table, err)
			}
		})
	}
}

func writeFailingNft(t *testing.T, diagnostic string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "diagnostic"), []byte(diagnostic), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nft")
	const script = `#!/bin/sh
script_dir=${0%/*}
/bin/cat "$script_dir/diagnostic" >&2
exit 1
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeSuccessfulNftIdentity(t *testing.T, table string, marker string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nft")
	document := `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"` +
		table + `","handle":42,"comment":"` + marker + `"}}]}`
	script := "#!/bin/sh\nprintf '%s\\n' '" + document + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
