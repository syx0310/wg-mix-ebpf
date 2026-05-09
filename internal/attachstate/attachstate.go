package attachstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

const (
	FileName          = "attach-state.json"
	DefaultStateDir   = "/var/lib/wg-mix-ebpf"
	EnvStateDir       = "WG_MIX_EBPF_VAR_LIB_DIR"
	currentVersion    = 1
	ingressHandle     = 0x10001
	egressHandle      = 0x10002
	defaultLinkRole   = "transform"
	defaultLinkParser = "auto"
)

type State struct {
	Version    int        `json:"version"`
	ConfigPath string     `json:"config_path"`
	UpdatedAt  time.Time  `json:"updated_at"`
	Underlays  []Underlay `json:"underlays"`
}

type Underlay struct {
	Name          string `json:"name"`
	IfName        string `json:"ifname,omitempty"`
	IfIndex       int    `json:"ifindex"`
	Role          string `json:"role,omitempty"`
	IngressHandle uint32 `json:"ingress_handle,omitempty"`
	EgressHandle  uint32 `json:"egress_handle,omitempty"`
}

func StateDir(path string) string {
	if path != "" {
		return path
	}
	if env := os.Getenv(EnvStateDir); env != "" {
		return env
	}
	return DefaultStateDir
}

func Path(stateDir string) string {
	return filepath.Join(StateDir(stateDir), FileName)
}

func Load(stateDir string) (*State, error) {
	data, err := os.ReadFile(Path(stateDir))
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse attach state: %w", err)
	}
	if state.Version != currentVersion {
		return nil, fmt.Errorf("unsupported attach state version %d", state.Version)
	}
	return &state, nil
}

func Save(stateDir string, state *State) error {
	dir := StateDir(stateDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create attach state dir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := Path(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write attach state: %w", err)
	}
	return os.Rename(tmp, Path(stateDir))
}

func Remove(stateDir string) error {
	if err := os.Remove(Path(stateDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove attach state: %w", err)
	}
	return nil
}

func FromControlState(configPath string, state *control.State) *State {
	out := &State{
		Version:    currentVersion,
		ConfigPath: configPath,
		UpdatedAt:  time.Now(),
	}
	if state == nil {
		return out
	}
	for _, u := range state.Underlays {
		if !u.Resolved || u.IfIndex == 0 || u.Role == "parse_only" || u.Role == "disabled" {
			continue
		}
		role := u.Role
		if role == "" {
			role = defaultLinkRole
		}
		out.Underlays = append(out.Underlays, Underlay{
			Name:          u.Name,
			IfName:        u.IfName,
			IfIndex:       u.IfIndex,
			Role:          role,
			IngressHandle: ingressHandle,
			EgressHandle:  egressHandle,
		})
	}
	return out
}

func ToControlState(state *State) *control.State {
	out := &control.State{}
	if state == nil {
		return out
	}
	for i, u := range state.Underlays {
		if u.IfIndex == 0 {
			continue
		}
		role := u.Role
		if role == "" {
			role = defaultLinkRole
		}
		out.Underlays = append(out.Underlays, control.UnderlayState{
			ID:       uint32(i + 1),
			Name:     u.Name,
			IfName:   u.IfName,
			IfIndex:  u.IfIndex,
			Parser:   defaultLinkParser,
			Role:     role,
			Resolved: true,
		})
	}
	return out
}

func MergeControlStates(states ...*control.State) *control.State {
	out := &control.State{}
	seen := make(map[int]struct{})
	for _, state := range states {
		if state == nil {
			continue
		}
		for _, u := range state.Underlays {
			if !u.Resolved || u.IfIndex == 0 {
				continue
			}
			if _, ok := seen[u.IfIndex]; ok {
				continue
			}
			seen[u.IfIndex] = struct{}{}
			out.Underlays = append(out.Underlays, u)
		}
	}
	return out
}

func StaleControlState(previous *State, current *control.State) *control.State {
	if previous == nil {
		return &control.State{}
	}
	active := make(map[int]struct{})
	if current != nil {
		for _, u := range current.Underlays {
			if u.Resolved && u.IfIndex != 0 && u.Role != "disabled" {
				active[u.IfIndex] = struct{}{}
			}
		}
	}
	stale := &control.State{}
	for i, u := range previous.Underlays {
		if u.IfIndex == 0 {
			continue
		}
		if _, ok := active[u.IfIndex]; ok {
			continue
		}
		stale.Underlays = append(stale.Underlays, control.UnderlayState{
			ID:       uint32(i + 1),
			Name:     u.Name,
			IfName:   u.IfName,
			IfIndex:  u.IfIndex,
			Parser:   defaultLinkParser,
			Role:     u.Role,
			Resolved: true,
		})
	}
	return stale
}
