package profile

import (
	"fmt"

	"github.com/syx0310/wg-mix-ebpf/internal/config"
)

const (
	StandardInitiation    uint32 = 0x00000001
	StandardResponse      uint32 = 0x00000002
	StandardCookieReply   uint32 = 0x00000003
	StandardTransportData uint32 = 0x00000004
)

var Standard = [4]uint32{
	StandardInitiation,
	StandardResponse,
	StandardCookieReply,
	StandardTransportData,
}

var WireguardMixWireValuesV1 = [4]uint32{
	0xf658c2e6,
	0x0686b1d0,
	0x075ae5e0,
	0x13dff06b,
}

type Compiled struct {
	Name            string
	StandardToMixed [4]uint32
	MixedToStandard [4]uint32
}

func CompileAll(profiles map[string]config.Profile) (map[string]Compiled, error) {
	out := make(map[string]Compiled, len(profiles))
	for name, cfg := range profiles {
		compiled, err := Compile(name, cfg)
		if err != nil {
			return nil, err
		}
		out[name] = compiled
	}
	return out, nil
}

func Compile(name string, cfg config.Profile) (Compiled, error) {
	if name == "" {
		return Compiled{}, fmt.Errorf("profile name is required")
	}
	if cfg.Index.Mode == "" {
		cfg.Index.Mode = "none"
	}
	if cfg.Index.Mode != "none" {
		return Compiled{}, fmt.Errorf("profile %q index mode %q is unsupported in MVP", name, cfg.Index.Mode)
	}

	mixed, err := mixedValues(cfg)
	if err != nil {
		return Compiled{}, fmt.Errorf("profile %q: %w", name, err)
	}
	if err := validateMixed(mixed, cfg.AllowPassthrough); err != nil {
		return Compiled{}, fmt.Errorf("profile %q: %w", name, err)
	}

	var reverse [4]uint32
	for i := range reverse {
		reverse[i] = Standard[i]
	}
	return Compiled{
		Name:            name,
		StandardToMixed: mixed,
		MixedToStandard: reverse,
	}, nil
}

func mixedValues(cfg config.Profile) ([4]uint32, error) {
	if cfg.Preset != "" {
		switch cfg.Preset {
		case "wireguard-mix-wire-values-v1":
			return WireguardMixWireValuesV1, nil
		default:
			return [4]uint32{}, fmt.Errorf("unsupported preset %q", cfg.Preset)
		}
	}
	values := [4]uint32{
		cfg.TypeWord.Initiation,
		cfg.TypeWord.Response,
		cfg.TypeWord.CookieReply,
		cfg.TypeWord.TransportData,
	}
	for i, v := range values {
		if v == 0 {
			return [4]uint32{}, fmt.Errorf("type_word value %d is zero", i)
		}
	}
	return values, nil
}

func validateMixed(values [4]uint32, allowPassthrough bool) error {
	seen := make(map[uint32]struct{}, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			return fmt.Errorf("mixed type_word 0x%08x is duplicated", v)
		}
		seen[v] = struct{}{}
		if !allowPassthrough && isStandard(v) {
			return fmt.Errorf("mixed type_word 0x%08x equals a standard type_word", v)
		}
	}
	return nil
}

func isStandard(v uint32) bool {
	for _, standard := range Standard {
		if v == standard {
			return true
		}
	}
	return false
}
