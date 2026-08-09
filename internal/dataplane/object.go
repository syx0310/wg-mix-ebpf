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

const EmbeddedObjectSource = "embedded:wg_mix_tc.o"

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
	embeddedObject, err := embeddedObjects.ReadFile("embedded/wg_mix_tc.o")
	if err != nil {
		return nil, ObjectIdentity{}, fmt.Errorf("embedded BPF object is unavailable; run make build to package it into the Go binary: %w", err)
	}
	if len(embeddedObject) == 0 {
		return nil, ObjectIdentity{}, fmt.Errorf("embedded BPF object is empty; run make build to package it into the Go binary")
	}
	identity := objectIdentity(EmbeddedObjectSource, true, embeddedObject)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedObject))
	if err != nil {
		return nil, identity, fmt.Errorf("load embedded BPF object: %w", err)
	}
	return spec, identity, nil
}

func EmbeddedObjectIdentity() (ObjectIdentity, error) {
	object, err := embeddedObjects.ReadFile("embedded/wg_mix_tc.o")
	if err != nil {
		return ObjectIdentity{}, fmt.Errorf("read embedded BPF object identity: %w", err)
	}
	if len(object) == 0 {
		return ObjectIdentity{}, fmt.Errorf("read embedded BPF object identity: object is empty")
	}
	return objectIdentity(EmbeddedObjectSource, true, object), nil
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

func DisplayObjectPath(explicit string) string {
	if path := objectPathFromEnv(explicit); path != "" {
		return path
	}
	return EmbeddedObjectSource
}
