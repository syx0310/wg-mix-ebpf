//go:build linux

package faketcp

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

const fakeTCPEventsKernelMapName = "faketcp_events"

type ringEventReader struct {
	reader *ringbuf.Reader
}

type perfEventReader struct {
	reader *perf.Reader
}

// NewLinuxEventReader constructs a reader while the caller holds a borrowed
// events-map handle. ringbuf.Reader owns its mmap/poller after construction;
// perf.Reader clones the map itself. The raw *ebpf.Map must not be retained by
// the caller or by this wrapper.
func NewLinuxEventReader(events *ebpf.Map, perCPUBuffer int) (EventReader, error) {
	if events == nil {
		return nil, errors.New("faketcp events eBPF map is nil")
	}
	info, err := events.Info()
	if err != nil {
		return nil, fmt.Errorf("inspect faketcp events map: %w", err)
	}
	if info.Name != fakeTCPEventsKernelMapName {
		return nil, fmt.Errorf("faketcp events kernel map name is %q, want %q", info.Name, fakeTCPEventsKernelMapName)
	}
	switch events.Type() {
	case ebpf.RingBuf:
		reader, err := ringbuf.NewReader(events)
		if err != nil {
			return nil, fmt.Errorf("open faketcp ring-buffer reader: %w", err)
		}
		return &ringEventReader{reader: reader}, nil
	case ebpf.PerfEventArray:
		if perCPUBuffer <= 0 {
			return nil, errors.New("faketcp perf-event reader buffer must be positive")
		}
		reader, err := perf.NewReader(events, perCPUBuffer)
		if err != nil {
			return nil, fmt.Errorf("open faketcp perf-event reader: %w", err)
		}
		return &perfEventReader{reader: reader}, nil
	default:
		return nil, fmt.Errorf("faketcp events map type %s is neither ring buffer nor perf event array", events.Type())
	}
}

func (reader *ringEventReader) Read() (EventRecord, error) {
	if reader == nil || reader.reader == nil {
		return EventRecord{}, errors.New("faketcp ring-buffer reader is nil")
	}
	record, err := reader.reader.Read()
	if err != nil {
		return EventRecord{}, err
	}
	return EventRecord{RawSample: append([]byte(nil), record.RawSample...)}, nil
}

func (reader *ringEventReader) SetDeadline(deadline time.Time) {
	if reader != nil && reader.reader != nil {
		reader.reader.SetDeadline(deadline)
	}
}

func (reader *ringEventReader) Close() error {
	if reader == nil || reader.reader == nil {
		return nil
	}
	return reader.reader.Close()
}

func (reader *perfEventReader) Read() (EventRecord, error) {
	if reader == nil || reader.reader == nil {
		return EventRecord{}, errors.New("faketcp perf-event reader is nil")
	}
	record, err := reader.reader.Read()
	if err != nil {
		return EventRecord{}, err
	}
	return EventRecord{
		RawSample:   canonicalPerfEventSample(record.RawSample),
		LostSamples: record.LostSamples,
	}, nil
}

func (reader *perfEventReader) SetDeadline(deadline time.Time) {
	if reader != nil && reader.reader != nil {
		reader.reader.SetDeadline(deadline)
	}
}

func (reader *perfEventReader) Close() error {
	if reader == nil || reader.reader == nil {
		return nil
	}
	return reader.reader.Close()
}
