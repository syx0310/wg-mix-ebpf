package dataplane

import (
	"strings"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

func TestPreflightProductionUnderlayParsers(t *testing.T) {
	tests := []struct {
		name    string
		state   *control.State
		wantErr string
	}{
		{name: "empty online state", state: &control.State{}},
		{name: "resolved ethernet", state: parserPreflightState(true, "transform", "ethernet")},
		{name: "resolved l3", state: parserPreflightState(true, "transform", "l3")},
		{name: "unresolved auto is offline", state: parserPreflightState(false, "transform", "auto")},
		{name: "resolved parse-only auto", state: parserPreflightState(true, "parse_only", "auto")},
		{name: "resolved disabled auto", state: parserPreflightState(true, "disabled", "auto")},
		{name: "resolved attachable auto", state: parserPreflightState(true, "transform", "auto"), wantErr: "parser \"auto\" is ambiguous"},
		{name: "resolved attachable empty", state: parserPreflightState(true, "underlay", ""), wantErr: "parser \"\" is ambiguous"},
		{name: "resolved attachable unknown", state: parserPreflightState(true, "", "raw"), wantErr: "parser \"raw\" is ambiguous"},
		{name: "nil state", wantErr: "control state is nil"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := preflightProductionUnderlayParsers(test.state)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("preflight production parsers: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("preflight error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func parserPreflightState(resolved bool, role, parser string) *control.State {
	return &control.State{Underlays: []control.UnderlayState{{
		Name: "uplink", IfIndex: 7, Role: role, Parser: parser, Resolved: resolved,
	}}}
}
