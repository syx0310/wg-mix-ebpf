package dataplane

import (
	"bytes"
	"embed"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

//go:embed embedded/*
var embeddedObjects embed.FS

func loadCollectionSpec(objectPath string) (*ebpf.CollectionSpec, string, error) {
	path := objectPathFromEnv(objectPath)
	if path != "" {
		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			return nil, path, fmt.Errorf("load BPF object %s: %w", path, err)
		}
		return spec, path, nil
	}
	embeddedObject, err := embeddedObjects.ReadFile("embedded/wg_mix_tc.o")
	if err != nil {
		return nil, "", fmt.Errorf("embedded BPF object is unavailable; run make build to package it into the Go binary: %w", err)
	}
	if len(embeddedObject) == 0 {
		return nil, "", fmt.Errorf("embedded BPF object is empty; run make build to package it into the Go binary")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedObject))
	if err != nil {
		return nil, "embedded:wg_mix_tc.o", fmt.Errorf("load embedded BPF object: %w", err)
	}
	return spec, "embedded:wg_mix_tc.o", nil
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
	return "embedded:wg_mix_tc.o"
}
