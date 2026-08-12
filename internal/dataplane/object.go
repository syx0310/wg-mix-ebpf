package dataplane

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

//go:embed embedded/*
var embeddedObjects embed.FS

const (
	EmbeddedObjectSource                 = "embedded:wg_mix_tc.o"
	EmbeddedFakeTCPObjectSource          = "embedded:wg_mix_faketcp.o"
	EmbeddedFakeTCPLegacy515ObjectSource = "embedded:wg_mix_faketcp_legacy_515.o"
)

type ObjectIdentity struct {
	Source   string `json:"source"`
	SHA256   string `json:"sha256"`
	Embedded bool   `json:"embedded"`
}

func loadCollectionSpec(objectPath string) (*ebpf.CollectionSpec, ObjectIdentity, error) {
	return loadCollectionSpecFromResolvedPath(objectPathFromEnv(objectPath))
}

// loadCollectionSpecFromResolvedPath does not consult the environment. An
// empty path selects the embedded object; a non-empty path is used exactly as
// supplied. Production coordinator handles use this after freezing their
// effective object source so scope validation and the eventual read cannot
// silently select different objects through a later environment lookup.
func loadCollectionSpecFromResolvedPath(path string) (*ebpf.CollectionSpec, ObjectIdentity, error) {
	if path != "" {
		object, err := os.ReadFile(path)
		if err != nil {
			return nil, ObjectIdentity{}, fmt.Errorf("read BPF object %s: %w", path, err)
		}
		identity := objectIdentity(path, false, object)
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
		if err != nil {
			return nil, identity, fmt.Errorf("load BPF object %s: %w", path, err)
		}
		return spec, identity, nil
	}
	return loadEmbeddedCollectionSpec("wg_mix_tc.o", EmbeddedObjectSource)
}

// loadFakeTCPCollectionSpecFromResolvedPath is deliberately separate from the
// baseline loader. An empty selector chooses the independently embedded
// FakeTCP object and can never fall back to wg_mix_tc.o.
func loadFakeTCPCollectionSpecFromResolvedPath(path string) (*ebpf.CollectionSpec, ObjectIdentity, error) {
	if path != "" {
		object, err := os.ReadFile(path)
		if err != nil {
			return nil, ObjectIdentity{}, fmt.Errorf("read FakeTCP BPF object %s: %w", path, err)
		}
		identity := objectIdentity(path, false, object)
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
		if err != nil {
			return nil, identity, fmt.Errorf("load FakeTCP BPF object %s: %w", path, err)
		}
		return spec, identity, nil
	}
	return loadEmbeddedCollectionSpec("wg_mix_faketcp.o", EmbeddedFakeTCPObjectSource)
}

// loadFakeTCPLegacy515CollectionSpecFromResolvedPath is deliberately separate
// from both baseline and modern FakeTCP loaders. The legacy object uses a
// kprobe checksum bridge and a Linux 5.15-compatible verifier contract, so it
// must never be selected through the modern object path or identity.
func loadFakeTCPLegacy515CollectionSpecFromResolvedPath(path string) (*ebpf.CollectionSpec, ObjectIdentity, error) {
	if path != "" {
		object, err := os.ReadFile(path)
		if err != nil {
			return nil, ObjectIdentity{}, fmt.Errorf("read legacy-5.15 FakeTCP BPF object %s: %w", path, err)
		}
		identity := objectIdentity(path, false, object)
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
		if err != nil {
			return nil, identity, fmt.Errorf("load legacy-5.15 FakeTCP BPF object %s: %w", path, err)
		}
		return spec, identity, nil
	}
	return loadEmbeddedCollectionSpec(
		"wg_mix_faketcp_legacy_515.o",
		EmbeddedFakeTCPLegacy515ObjectSource,
	)
}

func loadEmbeddedCollectionSpec(name, source string) (*ebpf.CollectionSpec, ObjectIdentity, error) {
	embeddedObject, err := embeddedObjects.ReadFile("embedded/" + name)
	if err != nil {
		return nil, ObjectIdentity{}, fmt.Errorf("embedded BPF object %s is unavailable; run make build to package it into the Go binary: %w", name, err)
	}
	if len(embeddedObject) == 0 {
		return nil, ObjectIdentity{}, fmt.Errorf("embedded BPF object %s is empty; run make build to package it into the Go binary", name)
	}
	identity := objectIdentity(source, true, embeddedObject)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedObject))
	if err != nil {
		return nil, identity, fmt.Errorf("load embedded BPF object %s: %w", name, err)
	}
	return spec, identity, nil
}

func EmbeddedObjectIdentity() (ObjectIdentity, error) {
	return embeddedObjectIdentity("wg_mix_tc.o", EmbeddedObjectSource)
}

func EmbeddedFakeTCPObjectIdentity() (ObjectIdentity, error) {
	return embeddedObjectIdentity("wg_mix_faketcp.o", EmbeddedFakeTCPObjectSource)
}

func EmbeddedFakeTCPLegacy515ObjectIdentity() (ObjectIdentity, error) {
	return embeddedObjectIdentity(
		"wg_mix_faketcp_legacy_515.o",
		EmbeddedFakeTCPLegacy515ObjectSource,
	)
}

func embeddedObjectIdentity(name, source string) (ObjectIdentity, error) {
	object, err := embeddedObjects.ReadFile("embedded/" + name)
	if err != nil {
		return ObjectIdentity{}, fmt.Errorf("read embedded BPF object %s identity: %w", name, err)
	}
	if len(object) == 0 {
		return ObjectIdentity{}, fmt.Errorf("read embedded BPF object %s identity: object is empty", name)
	}
	return objectIdentity(source, true, object), nil
}

func objectIdentity(source string, embedded bool, object []byte) ObjectIdentity {
	digest := sha256.Sum256(object)
	return ObjectIdentity{
		Source:   source,
		SHA256:   fmt.Sprintf("%x", digest),
		Embedded: embedded,
	}
}

func objectPathFromEnv(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if path := os.Getenv(EnvObjectPath); path != "" {
		return path
	}
	return ""
}

func fakeTCPObjectPathFromEnv(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv(EnvFakeTCPObjectPath)
}

func fakeTCPLegacy515ObjectPathFromEnv(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return os.Getenv(EnvFakeTCPLegacy515ObjectPath)
}

func DisplayObjectPath(explicit string) string {
	if path := objectPathFromEnv(explicit); path != "" {
		return path
	}
	return EmbeddedObjectSource
}
