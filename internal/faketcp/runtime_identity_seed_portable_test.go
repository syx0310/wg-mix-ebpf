package faketcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

type portableRuntimeIdentityMap struct {
	mu sync.Mutex

	info       ebpf.MapInfo
	identity   [32]byte
	sequences  []uint64
	writeCalls int
}

func (m *portableRuntimeIdentityMap) Info() (*ebpf.MapInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info := m.info
	return &info, nil
}

func (m *portableRuntimeIdentityMap) Lookup(_ any, valueOut any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch typed := valueOut.(type) {
	case *[32]byte:
		*typed = m.identity
	case []uint64:
		if len(typed) != len(m.sequences) {
			return fmt.Errorf("per-CPU lookup slots=%d want=%d", len(typed), len(m.sequences))
		}
		copy(typed, m.sequences)
	default:
		return fmt.Errorf("unexpected lookup output %T", valueOut)
	}
	return nil
}

func (m *portableRuntimeIdentityMap) Update(_ any, value any, _ ebpf.MapUpdateFlags) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeCalls++
	switch typed := value.(type) {
	case *abi.FakeTCPRuntimeIdentityValue:
		m.identity = [32]byte{}
		binary.NativeEndian.PutUint64(m.identity[0:8], typed.Generation)
		copy(m.identity[8:24], typed.Incarnation[:])
		binary.NativeEndian.PutUint16(m.identity[24:26], typed.EventABIVersion)
	case []uint64:
		if len(typed) != len(m.sequences) {
			return fmt.Errorf("per-CPU update slots=%d want=%d", len(typed), len(m.sequences))
		}
		m.sequences = append(m.sequences[:0], typed...)
	default:
		return fmt.Errorf("unexpected update value %T", value)
	}
	return nil
}

func (m *portableRuntimeIdentityMap) writes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeCalls
}

func portableRuntimeMaps(possibleCPUs int) (
	*portableRuntimeIdentityMap,
	*portableRuntimeIdentityMap,
) {
	return &portableRuntimeIdentityMap{info: ebpf.MapInfo{
			Name: fakeTCPRuntimeIdentityMapName, Type: ebpf.Array,
			KeySize: 4, ValueSize: 32, MaxEntries: 1,
		}}, &portableRuntimeIdentityMap{
			info: ebpf.MapInfo{
				Name: fakeTCPCaptureSequenceMapName, Type: ebpf.PerCPUArray,
				KeySize: 4, ValueSize: 8, MaxEntries: 1,
			},
			sequences: make([]uint64, possibleCPUs),
		}
}

func TestRuntimeIdentitySeedRejectsPersistedStateAndBadMapsBeforeWrites(t *testing.T) {
	const possibleCPUs = 4
	for _, test := range []struct {
		name   string
		mutate func(*portableRuntimeIdentityMap, *portableRuntimeIdentityMap)
	}{
		{
			name: "identity byte",
			mutate: func(identityMap, _ *portableRuntimeIdentityMap) {
				identityMap.identity[31] = 1
			},
		},
		{
			name: "identity contract",
			mutate: func(identityMap, _ *portableRuntimeIdentityMap) {
				identityMap.info.ValueSize--
			},
		},
		{
			name: "sequence contract",
			mutate: func(_ *portableRuntimeIdentityMap, sequenceMap *portableRuntimeIdentityMap) {
				sequenceMap.info.Type = ebpf.Array
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			identityMap, sequenceMap := portableRuntimeMaps(possibleCPUs)
			test.mutate(identityMap, sequenceMap)
			if err := seedLinuxRuntimeIdentity(
				identityMap,
				sequenceMap,
				RuntimeIdentity{Generation: 7, Incarnation: RuntimeIncarnation{1}},
				possibleCPUs,
			); err == nil {
				t.Fatal("persisted state or invalid map contract was accepted")
			}
			if identityMap.writes() != 0 || sequenceMap.writes() != 0 {
				t.Fatalf(
					"rejected seed wrote maps: identity=%d sequence=%d",
					identityMap.writes(), sequenceMap.writes(),
				)
			}
		})
	}

	for cpu := range possibleCPUs {
		t.Run(fmt.Sprintf("sequence CPU slot %d", cpu), func(t *testing.T) {
			identityMap, sequenceMap := portableRuntimeMaps(possibleCPUs)
			sequenceMap.sequences[cpu] = 1
			err := seedLinuxRuntimeIdentity(
				identityMap,
				sequenceMap,
				RuntimeIdentity{Generation: 7, Incarnation: RuntimeIncarnation{1}},
				possibleCPUs,
			)
			if !errors.Is(err, ErrLinuxRuntimeIdentityNamespaceNotFresh) {
				t.Fatalf("persisted sequence error=%v", err)
			}
			if identityMap.writes() != 0 || sequenceMap.writes() != 0 {
				t.Fatalf(
					"persisted sequence wrote maps: identity=%d sequence=%d",
					identityMap.writes(), sequenceMap.writes(),
				)
			}
		})
	}
}

func TestConcurrentRuntimeIdentitySeedSerializesPersistedFreshnessGuard(t *testing.T) {
	const possibleCPUs = 4
	identityMap, sequenceMap := portableRuntimeMaps(possibleCPUs)
	identity := RuntimeIdentity{Generation: 7, Incarnation: RuntimeIncarnation{1}}
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- seedLinuxRuntimeIdentity(
				identityMap, sequenceMap, identity, possibleCPUs,
			)
		}()
	}
	close(start)
	group.Wait()
	close(results)

	successes, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrLinuxRuntimeIdentityNamespaceNotFresh):
			rejected++
		default:
			t.Fatalf("unexpected seed result: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("concurrent seed results: success=%d rejected=%d", successes, rejected)
	}
	if identityMap.writes() != 2 || sequenceMap.writes() != 1 {
		t.Fatalf(
			"concurrent seed writes: identity=%d sequence=%d want=2/1",
			identityMap.writes(), sequenceMap.writes(),
		)
	}
}
