package dataplane

import (
	"errors"
	"fmt"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

// preflightProductionUnderlayParsers prevents a live attachment from
// publishing PARSER_AUTO. Auto remains a useful representation for offline
// state, unresolved discovery, and parse-only diagnostics, but it is
// ambiguous for a resolved interface that will run the production TC program.
func preflightProductionUnderlayParsers(state *control.State) error {
	if state == nil {
		return errors.New("preflight production underlay parsers: control state is nil")
	}
	for _, underlay := range state.Underlays {
		if !productionUnderlayIsAttachable(underlay) {
			continue
		}
		switch underlay.Parser {
		case "ethernet", "l3":
			continue
		default:
			return fmt.Errorf(
				"preflight production underlay %q (ifindex %d, role %q): parser %q is ambiguous; resolved attachable underlays require ethernet or l3 before dataplane mutation",
				underlay.Name,
				underlay.IfIndex,
				underlay.Role,
				underlay.Parser,
			)
		}
	}
	return nil
}

func productionUnderlayIsAttachable(underlay control.UnderlayState) bool {
	return underlay.Resolved && underlay.Role != "parse_only" && underlay.Role != "disabled"
}
