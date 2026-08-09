//go:build linux

package faketcp

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	fakeTCPStatsKernelMapName = "faketcp_stats_map"
	fakeTCPEventErrorStatKey  = uint32(8)
	fakeTCPStatsCount         = uint32(17)
)

type linuxEventLossCounter struct {
	mu sync.Mutex

	stats        *ebpf.Map
	possibleCPUs int
	values       []uint64
}

// NewLinuxRuntime consumes this factory capability only after both borrowed
// maps have the exact production identity and shape. events may be a
// short-lived clone: ringbuf.Reader owns its mmap/poller after construction.
// stats remains borrowed from the generation collection; the outer runtime
// must close this slow path before closing that collection.
func (factory ControllerRuntimeFactory) NewLinuxRuntime(
	engine *Engine,
	events *ebpf.Map,
	stats *ebpf.Map,
) (*ControllerRuntime, error) {
	if engine == nil {
		return nil, errors.New("build Linux faketcp controller runtime: Engine is nil")
	}
	eventMapID, err := inspectLinuxControllerMap(
		events,
		fakeTCPEventsKernelMapName,
		ebpf.RingBuf,
		0,
		0,
		1<<20,
	)
	if err != nil {
		return nil, fmt.Errorf("inspect faketcp production events map: %w", err)
	}
	statsMapID, err := inspectLinuxControllerMap(
		stats,
		fakeTCPStatsKernelMapName,
		ebpf.PerCPUArray,
		4,
		8,
		fakeTCPStatsCount,
	)
	if err != nil {
		return nil, fmt.Errorf("inspect faketcp production stats map: %w", err)
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("read possible CPUs for faketcp controller runtime: %w", err)
	}
	losses := &linuxEventLossCounter{
		stats: stats, possibleCPUs: possibleCPUs, values: make([]uint64, possibleCPUs),
	}
	initialLoss, err := losses.Count()
	if err != nil {
		return nil, fmt.Errorf("read initial faketcp kernel event-loss counter: %w", err)
	}
	if initialLoss != 0 {
		return nil, fmt.Errorf(
			"fresh faketcp generation has nonzero event-loss counter %d",
			initialLoss,
		)
	}
	claim, err := factory.claim(
		engine.Identity(),
		eventMapID,
		statsMapID,
		possibleCPUs,
	)
	if err != nil {
		return nil, err
	}

	ring, err := ringbuf.NewReader(events)
	if err != nil {
		return nil, fmt.Errorf("open production faketcp ring reader: %w", err)
	}
	ordered, err := newProductionEventReader(
		&ringEventReader{reader: ring},
		claim.binding.RuntimeIdentity,
		claim.possibleCPUs,
		losses,
		initialLoss,
	)
	if err != nil {
		return nil, errors.Join(err, closeControllerRuntimeResource("ring reader", ring))
	}
	writer, err := NewLinuxRawIPv4Writer(claim.rawSendTimeout)
	if err != nil {
		return nil, errors.Join(err, closeControllerRuntimeResource("event reader", ordered))
	}
	return newOwnedControllerRuntime(engine, ordered, writer, claim)
}

func inspectLinuxControllerMap(
	bpfMap *ebpf.Map,
	name string,
	mapType ebpf.MapType,
	keySize uint32,
	valueSize uint32,
	maxEntries uint32,
) (uint32, error) {
	if bpfMap == nil {
		return 0, errors.New("eBPF map is nil")
	}
	info, err := bpfMap.Info()
	if err != nil {
		return 0, fmt.Errorf("read eBPF map info: %w", err)
	}
	id, available := info.ID()
	if !available || id == 0 {
		return 0, errors.New("eBPF map ID is unavailable")
	}
	if info.Name != name || info.Type != mapType || info.KeySize != keySize ||
		info.ValueSize != valueSize || info.MaxEntries != maxEntries || info.Flags != 0 {
		return 0, fmt.Errorf(
			"map identity is name=%q type=%s key=%d value=%d max=%d flags=%#x; want name=%q type=%s key=%d value=%d max=%d flags=0",
			info.Name,
			info.Type,
			info.KeySize,
			info.ValueSize,
			info.MaxEntries,
			info.Flags,
			name,
			mapType,
			keySize,
			valueSize,
			maxEntries,
		)
	}
	return uint32(id), nil
}

func (counter *linuxEventLossCounter) Count() (uint64, error) {
	if counter == nil || counter.stats == nil || counter.possibleCPUs <= 0 ||
		len(counter.values) != counter.possibleCPUs {
		return 0, errors.New("faketcp Linux event-loss counter is unavailable")
	}
	counter.mu.Lock()
	defer counter.mu.Unlock()
	for index := range counter.values {
		counter.values[index] = 0
	}
	key := fakeTCPEventErrorStatKey
	if err := counter.stats.Lookup(&key, &counter.values); err != nil {
		return 0, fmt.Errorf("lookup stat %d: %w", key, err)
	}
	var total uint64
	for _, value := range counter.values {
		if value > math.MaxUint64-total {
			return 0, errors.New("faketcp Linux event-loss counter overflowed")
		}
		total += value
	}
	return total, nil
}
