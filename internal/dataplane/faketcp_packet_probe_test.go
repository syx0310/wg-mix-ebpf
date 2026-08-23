package dataplane

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeTCPPacketProbeRunner interface {
	Run(*ebpf.RunOptions) (uint32, error)
}

// runFakeTCPPacketProbe returns RunOptions.DataOut after Run. cilium/ebpf
// reslices that field to the kernel-reported data_size_out; retaining the
// caller's original backing slice would expose zero padding as packet bytes.
func runFakeTCPPacketProbe(
	runner fakeTCPPacketProbeRunner,
	packet []byte,
	context any,
	outputCapacity int,
) (uint32, []byte, error) {
	options := &ebpf.RunOptions{
		Data:    append([]byte(nil), packet...),
		DataOut: make([]byte, outputCapacity),
		Context: context,
		Repeat:  1,
	}
	result, err := runner.Run(options)
	return result, options.DataOut, err
}

type reslicingFakeTCPPacketProbeRunner struct {
	result uint32
	output []byte
}

func (runner reslicingFakeTCPPacketProbeRunner) Run(options *ebpf.RunOptions) (uint32, error) {
	copy(options.DataOut, runner.output)
	options.DataOut = options.DataOut[:len(runner.output)]
	return runner.result, nil
}

func TestRunFakeTCPPacketProbeUsesKernelReportedOutputLength(t *testing.T) {
	packet := []byte{1, 2, 3, 4}
	want := []byte{9, 8, 7, 6, 5}
	result, output, err := runFakeTCPPacketProbe(
		reslicingFakeTCPPacketProbeRunner{result: 17, output: want},
		packet,
		struct{}{},
		64,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result != 17 {
		t.Fatalf("result=%d, want 17", result)
	}
	if !bytes.Equal(output, want) {
		t.Fatalf("output=%v, want exact kernel-reported bytes %v", output, want)
	}
	if len(output) == 64 {
		t.Fatal("probe retained the caller allocation length instead of data_size_out")
	}
}
