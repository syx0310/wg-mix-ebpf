//go:build linux

package dataplane

import (
	"slices"
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestActiveAttachIfindexesSelectsOnlyExactTCXTargets(t *testing.T) {
	state := &control.State{Underlays: []control.UnderlayState{
		{Name: "egress", IfIndex: 17, Resolved: true},
		{Name: "unresolved", IfIndex: 13},
		{Name: "parse", IfIndex: 15, Resolved: true, Role: "parse_only"},
		{Name: "disabled", IfIndex: 16, Resolved: true, Role: "disabled"},
		{Name: "ingress", IfIndex: 11, Resolved: true},
	}}
	got, err := activeAttachIfindexes(state)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{11, 17}; !slices.Equal(got, want) {
		t.Fatalf("active TCX ifindexes = %v, want %v", got, want)
	}
}

func TestActiveAttachIfindexesRejectsAmbiguousTargets(t *testing.T) {
	tests := []struct {
		name  string
		state *control.State
		want  string
	}{
		{
			name: "invalid",
			state: &control.State{Underlays: []control.UnderlayState{
				{Name: "bad", IfIndex: 0, Resolved: true},
			}},
			want: "invalid ifindex",
		},
		{
			name: "duplicate",
			state: &control.State{Underlays: []control.UnderlayState{
				{Name: "first", IfIndex: 11, Resolved: true},
				{Name: "second", IfIndex: 11, Resolved: true},
			}},
			want: "duplicate ifindex",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := activeAttachIfindexes(test.state)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("active TCX target error = %v, want %q", err, test.want)
			}
		})
	}
}
