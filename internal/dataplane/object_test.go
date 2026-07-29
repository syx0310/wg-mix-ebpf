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
