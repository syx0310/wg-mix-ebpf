package guard

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type nfTableListerFunc func(context.Context) ([]NFTable, error)

func (fn nfTableListerFunc) ListTables(ctx context.Context) ([]NFTable, error) {
	return fn(ctx)
}

func TestDisabledExecutorUsesReadOnlyPreflightForEveryOperation(t *testing.T) {
	calls := 0
	executor := NewDisabledExecutorWithLister(nfTableListerFunc(func(context.Context) ([]NFTable, error) {
		calls++
		return []NFTable{
			{Family: "ip", Name: TableName},
			{Family: "inet", Name: "unrelated"},
		}, nil
	}))

	apply, err := executor.Apply(t.Context(), NftPlan{Table: "invalid-on-purpose"})
	if err != nil {
		t.Fatalf("disabled apply returned an error: %v", err)
	}
	cleanup, err := executor.Cleanup(t.Context())
	if err != nil {
		t.Fatalf("disabled cleanup returned an error: %v", err)
	}
	observation, err := executor.Observe(t.Context())
	if err != nil {
		t.Fatalf("disabled observation returned an error: %v", err)
	}

	want := Outcome{Observation: ObservationAbsent}
	for operation, got := range map[string]Outcome{
		"apply":   apply,
		"cleanup": cleanup,
		"observe": observation,
	} {
		if got != want {
			t.Fatalf("disabled %s outcome = %#v, want %#v", operation, got, want)
		}
	}
	if calls != 3 {
		t.Fatalf("read-only inventories = %d, want 3 fresh observations", calls)
	}
}

func TestProjectTablePreflightRejectsEveryINetProjectTableShape(t *testing.T) {
	tests := []struct {
		name  string
		table string
	}{
		{name: "legacy", table: TableName},
		{name: "valid-random-owner", table: TableName + "_0123456789abcdef0123456789abcdef"},
		{name: "damaged-random-owner", table: TableName + "_damaged-owner"},
		{name: "empty-random-suffix", table: TableName + "_"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			preflight := NewProjectTablePreflightWithLister(nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				return []NFTable{{Family: "inet", Name: test.table}}, nil
			}))
			outcome, err := preflight.Check(t.Context())
			if err == nil || !strings.Contains(err.Error(), test.table) {
				t.Fatalf("project table %q was accepted: outcome=%#v err=%v", test.table, outcome, err)
			}
			if outcome.Observation != ObservationUnknown || outcome.Mutated || outcome.Warning != nil {
				t.Fatalf("collision outcome = %#v, want unknown and non-mutating", outcome)
			}
		})
	}
}

func TestProjectTablePreflightAllowsOnlyNonProjectOrNonINetTables(t *testing.T) {
	preflight := NewProjectTablePreflightWithLister(nfTableListerFunc(func(context.Context) ([]NFTable, error) {
		return []NFTable{
			{Family: "ip", Name: TableName},
			{Family: "ip6", Name: TableName + "_foreign-family"},
			{Family: "inet", Name: TableName + "rail"},
			{Family: "inet", Name: "unrelated"},
		}, nil
	}))
	outcome, err := preflight.Check(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if outcome != (Outcome{Observation: ObservationAbsent}) {
		t.Fatalf("clean preflight outcome = %#v, want absent", outcome)
	}
}

func TestProjectTablePreflightErrorsFailClosed(t *testing.T) {
	sentinel := errors.New("netfilter inventory denied")
	tests := []struct {
		name      string
		ctx       func() context.Context
		preflight ProjectTablePreflight
		want      error
	}{
		{
			name: "inventory-error",
			ctx:  t.Context,
			preflight: NewProjectTablePreflightWithLister(nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				return nil, sentinel
			})),
			want: sentinel,
		},
		{
			name:      "nil-lister",
			ctx:       t.Context,
			preflight: NewProjectTablePreflightWithLister(nil),
		},
		{
			name: "malformed-inventory",
			ctx:  t.Context,
			preflight: NewProjectTablePreflightWithLister(nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				return []NFTable{{Family: "inet"}}, nil
			})),
		},
		{
			name: "duplicate-inventory",
			ctx:  t.Context,
			preflight: NewProjectTablePreflightWithLister(nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				return []NFTable{
					{Family: "inet", Name: "unrelated"},
					{Family: "inet", Name: "unrelated"},
				}, nil
			})),
		},
		{
			name: "cancelled-context",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			},
			preflight: NewProjectTablePreflightWithLister(nfTableListerFunc(func(context.Context) ([]NFTable, error) {
				t.Fatal("cancelled preflight called the inventory")
				return nil, nil
			})),
			want: context.Canceled,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome, err := test.preflight.Check(test.ctx())
			if err == nil {
				t.Fatalf("unsafe preflight succeeded: %#v", outcome)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("preflight error = %v, want errors.Is(%v)", err, test.want)
			}
			if outcome.Observation != ObservationUnknown || outcome.Mutated || outcome.Warning != nil {
				t.Fatalf("failed preflight outcome = %#v, want unknown and non-mutating", outcome)
			}
		})
	}
}

func TestDisabledExecutorZeroValueFailsClosed(t *testing.T) {
	outcome, err := (DisabledExecutor{}).Preflight(t.Context())
	if err == nil || outcome.Observation != ObservationUnknown || outcome.Mutated {
		t.Fatalf("zero-value disabled executor outcome/error = %#v / %v, want unknown error", outcome, err)
	}
}
