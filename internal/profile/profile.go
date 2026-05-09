package profile

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"

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

const TokenPrefix = "wgmix1"

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

func Preset(name string) (config.Profile, error) {
	switch name {
	case "wireguard-mix-wire-values-v1":
		return config.Profile{
			Preset: name,
			Index:  config.IndexProfile{Mode: "none"},
		}, nil
	default:
		return config.Profile{}, fmt.Errorf("unsupported preset %q", name)
	}
}

func GenerateRandom() (config.Profile, error) {
	var values [4]uint32
	seen := make(map[uint32]struct{}, len(values))
	for i := range values {
		for {
			v, err := randomUint32()
			if err != nil {
				return config.Profile{}, err
			}
			if v == 0 || isStandard(v) {
				continue
			}
			if _, exists := seen[v]; exists {
				continue
			}
			seen[v] = struct{}{}
			values[i] = v
			break
		}
	}
	cfg := config.Profile{
		TypeWord: config.TypeWordProfile{
			Initiation:    values[0],
			Response:      values[1],
			CookieReply:   values[2],
			TransportData: values[3],
		},
		Index: config.IndexProfile{Mode: "none"},
	}
	if _, err := Compile("generated", cfg); err != nil {
		return config.Profile{}, err
	}
	return cfg, nil
}

func EncodeToken(cfg config.Profile) (string, error) {
	if _, err := Compile("token", cfg); err != nil {
		return "", err
	}
	values, err := mixedValues(cfg)
	if err != nil {
		return "", err
	}
	payload := tokenPayload{
		Version:       1,
		Initiation:    values[0],
		Response:      values[1],
		CookieReply:   values[2],
		TransportData: values[3],
		IndexMode:     "none",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := crc32.ChecksumIEEE(data)
	return fmt.Sprintf("%s.%s.%08x", TokenPrefix, base64.RawURLEncoding.EncodeToString(data), sum), nil
}

func DecodeToken(token string) (config.Profile, error) {
	parts := splitToken(token)
	if len(parts) != 3 || parts[0] != TokenPrefix {
		return config.Profile{}, fmt.Errorf("invalid profile token format")
	}
	return decodeTokenParts(parts[1], parts[2])
}

func decodeTokenParts(encoded string, checksum string) (config.Profile, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return config.Profile{}, fmt.Errorf("decode token payload: %w", err)
	}
	want := fmt.Sprintf("%08x", crc32.ChecksumIEEE(data))
	if checksum != want {
		return config.Profile{}, fmt.Errorf("token checksum mismatch")
	}
	var payload tokenPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return config.Profile{}, fmt.Errorf("parse token payload: %w", err)
	}
	if payload.Version != 1 {
		return config.Profile{}, fmt.Errorf("unsupported token version %d", payload.Version)
	}
	if payload.IndexMode == "" {
		payload.IndexMode = "none"
	}
	cfg := config.Profile{
		TypeWord: config.TypeWordProfile{
			Initiation:    payload.Initiation,
			Response:      payload.Response,
			CookieReply:   payload.CookieReply,
			TransportData: payload.TransportData,
		},
		Index: config.IndexProfile{Mode: payload.IndexMode},
	}
	if _, err := Compile("token", cfg); err != nil {
		return config.Profile{}, err
	}
	return cfg, nil
}

type tokenPayload struct {
	Version       int    `json:"v"`
	Initiation    uint32 `json:"i"`
	Response      uint32 `json:"r"`
	CookieReply   uint32 `json:"c"`
	TransportData uint32 `json:"t"`
	IndexMode     string `json:"x"`
}

func randomUint32() (uint32, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, fmt.Errorf("generate random type_word: %w", err)
	}
	return uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24, nil
}

func splitToken(token string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(token); i++ {
		if i == len(token) || token[i] == '.' {
			out = append(out, token[start:i])
			start = i + 1
		}
	}
	return out
}
