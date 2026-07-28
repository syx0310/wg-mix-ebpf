//go:build linux

package dataplane

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestXORTailCallBankStartAlternatesWithoutOverlap(t *testing.T) {
	tests := []struct {
		generation uint64
		want       uint32
	}{
		{generation: 0, want: 0},
		{generation: 1, want: xorSegmentCount},
		{generation: 2, want: 0},
		{generation: 3, want: xorSegmentCount},
	}
	for _, tt := range tests {
		if got := xorTailCallBankStart(tt.generation); got != tt.want {
			t.Fatalf("generation %d bank start = %d, want %d", tt.generation, got, tt.want)
		}
	}
}

func TestXORTailCallBindingsCoverEverySegment(t *testing.T) {
	if len(xorTailCallBindings) != 2 {
		t.Fatalf("tail-call map bindings = %d, want 2", len(xorTailCallBindings))
	}
	seenMaps := make(map[string]struct{})
	seenPrograms := make(map[string]struct{})
	for _, binding := range xorTailCallBindings {
		if _, duplicate := seenMaps[binding.mapName]; duplicate {
			t.Fatalf("duplicate tail-call map %q", binding.mapName)
		}
		seenMaps[binding.mapName] = struct{}{}
		for segment, name := range binding.programNames {
			if name == "" {
				t.Fatalf("%s segment %d has no program", binding.mapName, segment)
			}
			if _, duplicate := seenPrograms[name]; duplicate {
				t.Fatalf("duplicate tail-call program %q", name)
			}
			seenPrograms[name] = struct{}{}
		}
	}
	if len(seenPrograms) != len(xorTailCallBindings)*xorSegmentCount {
		t.Fatalf("tail-call programs = %d, want %d", len(seenPrograms), len(xorTailCallBindings)*xorSegmentCount)
	}
}

func TestPopulateXORTailCallsRejectsMissingLayout(t *testing.T) {
	t.Run("map", func(t *testing.T) {
		err := populateXORTailCalls(&ebpf.Collection{}, 1)
		if err == nil || !strings.Contains(err.Error(), `missing map "xor_egress_programs"`) {
			t.Fatalf("error = %v, want missing egress ProgramArray", err)
		}
	})

	t.Run("program", func(t *testing.T) {
		coll := &ebpf.Collection{
			Maps: map[string]*ebpf.Map{
				"xor_egress_programs": {},
			},
			Programs: map[string]*ebpf.Program{},
		}
		err := populateXORTailCalls(coll, 1)
		if err == nil || !strings.Contains(err.Error(), `missing program "wg_xor_eg_0"`) {
			t.Fatalf("error = %v, want missing first egress segment", err)
		}
	})
}
