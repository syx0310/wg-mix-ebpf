package faketcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

var benchmarkCheckpointSink ActionCheckpoint

type benchmarkRecoveryBackend struct{}

func (benchmarkRecoveryBackend) SendControl(
	context.Context,
	abi.FakeTCPSessionKey,
	uint32,
	ControlPacket,
) error {
	return nil
}

func (benchmarkRecoveryBackend) Reinject(
	context.Context,
	abi.FakeTCPSessionKey,
	PendingPacket,
) error {
	return nil
}

func (benchmarkRecoveryBackend) Close() error { return nil }

func BenchmarkActionCheckpointClone(b *testing.B) {
	for _, packetCount := range []int{1, 2, 8} {
		b.Run(fmt.Sprintf("packets=%d", packetCount), func(b *testing.B) {
			checkpoint := benchmarkActionCheckpoint(packetCount, 1280)
			b.ReportAllocs()
			b.SetBytes(int64(packetCount * 1280))
			b.ResetTimer()
			for range b.N {
				benchmarkCheckpointSink = cloneActionCheckpoint(checkpoint)
			}
		})
	}
}

func BenchmarkActionRecoveryExecute(b *testing.B) {
	ctx := context.Background()
	for _, packetCount := range []int{1, 2, 8} {
		b.Run(fmt.Sprintf("packets=%d", packetCount), func(b *testing.B) {
			store := NewMemoryActionCheckpointStore()
			recovery, err := NewActionRecovery(
				testRecoveryIdentity(),
				benchmarkRecoveryBackend{},
				store,
			)
			if err != nil {
				b.Fatal(err)
			}
			actions := benchmarkRecoveryActions(packetCount, 1280)
			b.ReportAllocs()
			b.SetBytes(int64(packetCount * 1280))
			b.ResetTimer()
			for range b.N {
				if err := recovery.Execute(ctx, actions); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkRecoveryActions(packetCount, packetSize int) []Action {
	flow := testFlow(31001)
	packets := make([]PendingPacket, packetCount)
	for index := range packets {
		packets[index] = PendingPacket{
			Data:               make([]byte, packetSize),
			CaptureNanos:       uint64(index + 1),
			CaptureFingerprint: [32]byte{1},
			CaptureID: CaptureIdentity{
				Runtime:  testRecoveryIdentity(),
				CPU:      1,
				Sequence: uint64(index + 1),
			},
		}
	}
	return []Action{{
		Kind:    ActionReleasePending,
		Flow:    flow,
		Packets: packets,
		Reason:  "benchmark-release",
	}}
}

func benchmarkActionCheckpoint(packetCount, packetSize int) ActionCheckpoint {
	actions := benchmarkRecoveryActions(packetCount, packetSize)
	steps, err := actionSteps(actions)
	if err != nil {
		panic(err)
	}
	return ActionCheckpoint{
		Revision:  1,
		Operation: 1,
		Identity:  testRecoveryIdentity(),
		Phase:     ActionCheckpointPrepared,
		Steps:     steps,
	}
}
