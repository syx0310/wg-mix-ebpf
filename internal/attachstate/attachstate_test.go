package attachstate

import (
	"path/filepath"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestAttachStateRoundTripAndMerge(t *testing.T) {
	dir := t.TempDir()
	state := &control.State{
		Underlays: []control.UnderlayState{
			{Name: "wan", IfName: "eth0", IfIndex: 10, Role: "transform", Resolved: true},
			{Name: "disabled", IfIndex: 11, Role: "disabled", Resolved: true},
		},
	}
	saved := FromControlState("/tmp/config.yaml", state)
	if len(saved.Underlays) != 1 {
		t.Fatalf("saved underlays = %d", len(saved.Underlays))
	}
	if err := Save(dir, saved); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Underlays[0].IfIndex != 10 {
		t.Fatalf("loaded ifindex = %d", loaded.Underlays[0].IfIndex)
	}
	merged := MergeControlStates(ToControlState(loaded), &control.State{
		Underlays: []control.UnderlayState{{Name: "new", IfIndex: 12, Resolved: true}},
	})
	if len(merged.Underlays) != 2 {
		t.Fatalf("merged underlays = %d", len(merged.Underlays))
	}
	if Path(dir) != filepath.Join(dir, FileName) {
		t.Fatalf("unexpected attach state path %q", Path(dir))
	}
}

func TestStaleControlState(t *testing.T) {
	previous := &State{
		Version: currentVersion,
		Underlays: []Underlay{
			{Name: "old", IfIndex: 10},
			{Name: "kept", IfIndex: 11},
		},
	}
	current := &control.State{
		Underlays: []control.UnderlayState{{Name: "kept", IfIndex: 11, Resolved: true}},
	}
	stale := StaleControlState(previous, current)
	if len(stale.Underlays) != 1 || stale.Underlays[0].IfIndex != 10 {
		t.Fatalf("unexpected stale state: %#v", stale.Underlays)
	}
}
