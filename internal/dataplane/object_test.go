package dataplane

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestObjectIdentity(t *testing.T) {
	object := []byte("deterministic BPF object bytes")
	want := sha256.Sum256(object)
	identity := objectIdentity("test.o", false, object)
	if identity.Source != "test.o" {
		t.Fatalf("source = %q, want test.o", identity.Source)
	}
	if identity.Embedded {
		t.Fatal("external object reported as embedded")
	}
	if identity.SHA256 != fmt.Sprintf("%x", want) {
		t.Fatalf("SHA-256 = %q, want %x", identity.SHA256, want)
	}
}

func TestLoadCollectionSpecHashesTheBytesItParses(t *testing.T) {
	object := []byte("not an ELF object")
	path := filepath.Join(t.TempDir(), "override.o")
	if err := os.WriteFile(path, object, 0o600); err != nil {
		t.Fatal(err)
	}
	spec, identity, err := loadCollectionSpec(path)
	if err == nil {
		t.Fatal("invalid object unexpectedly parsed")
	}
	if spec != nil {
		t.Fatalf("spec = %#v, want nil", spec)
	}
	want := sha256.Sum256(object)
	if identity.Source != path || identity.Embedded ||
		identity.SHA256 != fmt.Sprintf("%x", want) {
		t.Fatalf("object identity = %#v, want source=%q sha256=%x", identity, path, want)
	}
}

func TestEmbeddedObjectIdentityIsExplicitWhenUnavailable(t *testing.T) {
	identity, err := EmbeddedObjectIdentity()
	if err != nil {
		if identity != (ObjectIdentity{}) {
			t.Fatalf("identity on error = %#v, want zero value", identity)
		}
		return
	}
	if identity.Source != EmbeddedObjectSource || !identity.Embedded {
		t.Fatalf("embedded identity = %#v", identity)
	}
	if len(identity.SHA256) != 64 {
		t.Fatalf("embedded SHA-256 = %q", identity.SHA256)
	}
}

func TestEmbeddedFakeTCPObjectIdentityIsIndependent(t *testing.T) {
	if EmbeddedFakeTCPObjectSource == EmbeddedObjectSource {
		t.Fatal("FakeTCP and baseline embedded object sources are identical")
	}
	identity, err := EmbeddedFakeTCPObjectIdentity()
	if err != nil {
		if identity != (ObjectIdentity{}) {
			t.Fatalf("identity on error = %#v, want zero value", identity)
		}
		return
	}
	if identity.Source != EmbeddedFakeTCPObjectSource || !identity.Embedded {
		t.Fatalf("embedded FakeTCP identity = %#v", identity)
	}
	if len(identity.SHA256) != 64 {
		t.Fatalf("embedded FakeTCP SHA-256 = %q", identity.SHA256)
	}
}

func TestEmbeddedFakeTCPLegacy515ObjectIdentityIsIndependent(t *testing.T) {
	if EmbeddedFakeTCPLegacy515ObjectSource == EmbeddedObjectSource ||
		EmbeddedFakeTCPLegacy515ObjectSource == EmbeddedFakeTCPObjectSource {
		t.Fatal("legacy-5.15 FakeTCP and other embedded object sources are identical")
	}
	identity, err := EmbeddedFakeTCPLegacy515ObjectIdentity()
	if err != nil {
		if identity != (ObjectIdentity{}) {
			t.Fatalf("unavailable embedded legacy object returned identity %#v", identity)
		}
		return
	}
	if identity.Source != EmbeddedFakeTCPLegacy515ObjectSource || !identity.Embedded {
		t.Fatalf("embedded legacy-5.15 FakeTCP identity = %#v", identity)
	}
}

func TestFakeTCPObjectSelectorIsIndependentFromBaseline(t *testing.T) {
	t.Setenv(EnvObjectPath, "/objects/baseline.o")
	t.Setenv(EnvFakeTCPObjectPath, "/objects/faketcp.o")
	if got := fakeTCPObjectPathFromEnv(""); got != "/objects/faketcp.o" {
		t.Fatalf("FakeTCP object = %q, want independent environment selection", got)
	}
	if got := fakeTCPObjectPathFromEnv("/explicit/faketcp.o"); got != "/explicit/faketcp.o" {
		t.Fatalf("explicit FakeTCP object = %q", got)
	}
	t.Setenv(EnvFakeTCPObjectPath, "")
	if got := fakeTCPObjectPathFromEnv(""); got != "" {
		t.Fatalf("FakeTCP object inherited baseline selector: %q", got)
	}
}

func TestFakeTCPLegacy515ObjectSelectorIsIndependent(t *testing.T) {
	t.Setenv(EnvObjectPath, "/objects/baseline.o")
	t.Setenv(EnvFakeTCPObjectPath, "/objects/faketcp-modern.o")
	t.Setenv(EnvFakeTCPLegacy515ObjectPath, "/objects/faketcp-legacy-515.o")
	if got := fakeTCPLegacy515ObjectPathFromEnv(""); got != "/objects/faketcp-legacy-515.o" {
		t.Fatalf("legacy-5.15 FakeTCP object = %q", got)
	}
	if got := fakeTCPLegacy515ObjectPathFromEnv("/explicit/legacy.o"); got != "/explicit/legacy.o" {
		t.Fatalf("explicit legacy-5.15 FakeTCP object = %q", got)
	}
	t.Setenv(EnvFakeTCPLegacy515ObjectPath, "")
	if got := fakeTCPLegacy515ObjectPathFromEnv(""); got != "" {
		t.Fatalf("legacy selector inherited another object path: %q", got)
	}
}
