//go:build linux

package faketcp

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type fakeRuntimeIdentityMapBorrower struct {
	trace     *[]string
	callbacks int
	err       error
}

func (borrower *fakeRuntimeIdentityMapBorrower) WithRuntimeIdentityMaps(
	callback func(*ebpf.Map, *ebpf.Map) error,
) error {
	*borrower.trace = append(*borrower.trace, "borrow-identity-maps")
	for range borrower.callbacks {
		if err := callback(nil, nil); err != nil {
			return err
		}
	}
	return borrower.err
}

type fakeRuntimeIdentityMap struct {
	info       ebpf.MapInfo
	failUpdate int
	updates    int
	operations *[]string
}

func (m *fakeRuntimeIdentityMap) Info() (*ebpf.MapInfo, error) {
	info := m.info
	return &info, nil
}

func (m *fakeRuntimeIdentityMap) Update(_ any, value any, _ ebpf.MapUpdateFlags) error {
	m.updates++
	if m.failUpdate == m.updates {
		return errors.New("injected map update failure")
	}
	switch typed := value.(type) {
	case *abi.FakeTCPRuntimeIdentityValue:
		if *typed == (abi.FakeTCPRuntimeIdentityValue{}) {
			*m.operations = append(*m.operations, "disable")
		} else {
			*m.operations = append(*m.operations, fmt.Sprintf(
				"commit:%d:%d", typed.Generation, typed.EventABIVersion,
			))
		}
	case []uint64:
		*m.operations = append(*m.operations, fmt.Sprintf("reset:%d", len(typed)))
	default:
		return fmt.Errorf("unexpected update value %T", value)
	}
	return nil
}

func TestSeedLinuxRuntimeIdentityCommitsIdentityLast(t *testing.T) {
	operations := []string{}
	identityMap, sequenceMap := fakeRuntimeMaps(&operations)
	identity := RuntimeIdentity{Generation: 7, Incarnation: RuntimeIncarnation{1, 2, 3}}
	if err := seedLinuxRuntimeIdentity(identityMap, sequenceMap, identity, 4); err != nil {
		t.Fatal(err)
	}
	if want := []string{"disable", "reset:4", "commit:7:1"}; !slices.Equal(operations, want) {
		t.Fatalf("seed operations=%v want=%v", operations, want)
	}
}

func TestSeedLinuxRuntimeIdentityFailureNeverPublishesIdentityEarly(t *testing.T) {
	for _, test := range []struct {
		name             string
		failIdentityCall int
		failSequenceCall int
		want             []string
	}{
		{name: "disable", failIdentityCall: 1},
		{name: "sequence", failSequenceCall: 1, want: []string{"disable"}},
		{name: "commit", failIdentityCall: 2, want: []string{"disable", "reset:4"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			operations := []string{}
			identityMap, sequenceMap := fakeRuntimeMaps(&operations)
			identityMap.failUpdate = test.failIdentityCall
			sequenceMap.failUpdate = test.failSequenceCall
			err := seedLinuxRuntimeIdentity(identityMap, sequenceMap, RuntimeIdentity{
				Generation: 7, Incarnation: RuntimeIncarnation{1},
			}, 4)
			if err == nil {
				t.Fatal("injected seed failure was ignored")
			}
			if !slices.Equal(operations, test.want) {
				t.Fatalf("seed operations=%v want=%v", operations, test.want)
			}
		})
	}
}

func TestSeedLinuxRuntimeIdentityValidatesBothMapsBeforeDisablingEmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*fakeRuntimeIdentityMap, *fakeRuntimeIdentityMap)
	}{
		{
			name: "identity map",
			mutate: func(identityMap, _ *fakeRuntimeIdentityMap) {
				identityMap.info.ValueSize--
			},
		},
		{
			name: "sequence map",
			mutate: func(_ *fakeRuntimeIdentityMap, sequenceMap *fakeRuntimeIdentityMap) {
				sequenceMap.info.MaxEntries++
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			operations := []string{}
			identityMap, sequenceMap := fakeRuntimeMaps(&operations)
			test.mutate(identityMap, sequenceMap)
			err := seedLinuxRuntimeIdentity(identityMap, sequenceMap, RuntimeIdentity{
				Generation: 7, Incarnation: RuntimeIncarnation{1},
			}, 4)
			if err == nil {
				t.Fatal("invalid runtime map contract was accepted")
			}
			if len(operations) != 0 {
				t.Fatalf("map validation failure mutated runtime maps: %v", operations)
			}
		})
	}
}

func TestLinuxRuntimeIdentityPreCommitBorrowsAndSeedsExactlyOnce(t *testing.T) {
	engine, _ := testEngine(t, nil)
	trace := []string{}
	borrower := &fakeRuntimeIdentityMapBorrower{trace: &trace, callbacks: 1}
	hook, err := newLinuxRuntimeIdentityPreCommit(
		engine,
		borrower,
		func(_ *ebpf.Map, _ *ebpf.Map, gotEngine *Engine) error {
			if gotEngine != engine {
				t.Fatal("pre-commit seeded a different Engine identity")
			}
			trace = append(trace, "seed")
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := hook.PrepareUnreachableGeneration(); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"borrow-identity-maps", "seed"}; !slices.Equal(trace, want) {
		t.Fatalf("pre-commit trace=%v want=%v", trace, want)
	}
}

func TestLinuxRuntimeIdentityPreCommitRejectsMissingOrRepeatedBorrowCallback(t *testing.T) {
	engine, _ := testEngine(t, nil)
	for _, callbacks := range []int{0, 2} {
		t.Run(fmt.Sprintf("callbacks-%d", callbacks), func(t *testing.T) {
			trace := []string{}
			hook, err := newLinuxRuntimeIdentityPreCommit(
				engine,
				&fakeRuntimeIdentityMapBorrower{trace: &trace, callbacks: callbacks},
				func(*ebpf.Map, *ebpf.Map, *Engine) error {
					trace = append(trace, "seed")
					return nil
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := hook.PrepareUnreachableGeneration(); err == nil {
				t.Fatal("invalid borrowed-map callback count was accepted")
			}
		})
	}
}

func TestLinuxRuntimeIdentityPreCommitRetainsFirstFailure(t *testing.T) {
	engine, _ := testEngine(t, nil)
	trace := []string{}
	seedErr := errors.New("injected seed failure")
	hook, err := newLinuxRuntimeIdentityPreCommit(
		engine,
		&fakeRuntimeIdentityMapBorrower{trace: &trace, callbacks: 1},
		func(*ebpf.Map, *ebpf.Map, *Engine) error {
			trace = append(trace, "seed")
			return seedErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := hook.PrepareUnreachableGeneration(); !errors.Is(err, seedErr) {
			t.Fatalf("sticky preparation error=%v want=%v", err, seedErr)
		}
	}
	if want := []string{"borrow-identity-maps", "seed"}; !slices.Equal(trace, want) {
		t.Fatalf("failed pre-commit retried side effects: trace=%v want=%v", trace, want)
	}
}

func fakeRuntimeMaps(operations *[]string) (*fakeRuntimeIdentityMap, *fakeRuntimeIdentityMap) {
	return &fakeRuntimeIdentityMap{
			info: ebpf.MapInfo{
				Name: fakeTCPRuntimeIdentityMapName, Type: ebpf.Array,
				KeySize: 4, ValueSize: 32, MaxEntries: 1,
			},
			operations: operations,
		}, &fakeRuntimeIdentityMap{
			info: ebpf.MapInfo{
				Name: fakeTCPCaptureSequenceMapName, Type: ebpf.PerCPUArray,
				KeySize: 4, ValueSize: 8, MaxEntries: 1,
			},
			operations: operations,
		}
}
