package dataplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeTCPProductionRealTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve test temporary directory: %v", err)
	}
	return root
}

func TestCanonicalFakeTCPProductionPathAcceptsOnlyUnaliasedCanonicalPaths(t *testing.T) {
	root := fakeTCPProductionRealTempDir(t)
	existingDirectory := filepath.Join(root, "existing")
	if err := os.MkdirAll(existingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	existingFile := filepath.Join(existingDirectory, "object.o")
	if err := os.WriteFile(existingFile, []byte("object"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		existingFile,
		filepath.Join(existingDirectory, "not-created", "pin-leaf"),
	} {
		got, err := canonicalFakeTCPProductionPath("test", path)
		if err != nil {
			t.Fatalf("canonicalFakeTCPProductionPath(%q): %v", path, err)
		}
		if got != path {
			t.Fatalf("canonical path = %q, want exact %q", got, path)
		}
	}

	symlinkTarget := filepath.Join(root, "symlink-target")
	if err := os.MkdirAll(symlinkTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(root, "alias")
	if err := os.Symlink(symlinkTarget, symlinkPath); err != nil {
		t.Fatal(err)
	}
	invalid := []struct {
		name        string
		path        string
		wantMessage string
	}{
		{name: "relative", path: "relative/object.o", wantMessage: "not absolute"},
		{
			name: "non-clean",
			path: existingDirectory + string(os.PathSeparator) + ".." +
				string(os.PathSeparator) + "object.o",
			wantMessage: "not canonical",
		},
		{name: "root", path: string(os.PathSeparator), wantMessage: "filesystem root"},
		{
			name:        "symlink-component",
			path:        filepath.Join(symlinkPath, "object.o"),
			wantMessage: "symbolic-link component",
		},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, err := canonicalFakeTCPProductionPath("test", test.path)
			if err == nil || !strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("path %q error = %v, want %q", test.path, err, test.wantMessage)
			}
		})
	}
}

func TestFakeTCPProductionScopeIdentityValidatesObjectSourceKind(t *testing.T) {
	filesystem := fakeTCPProductionTestScope()
	if err := filesystem.validate(); err != nil {
		t.Fatalf("valid filesystem scope: %v", err)
	}
	embedded := filesystem
	embedded.objectKind = fakeTCPProductionObjectScopeEmbedded
	embedded.objectPath = EmbeddedObjectSource
	if err := embedded.validate(); err != nil {
		t.Fatalf("valid embedded scope: %v", err)
	}

	tests := []struct {
		name  string
		scope fakeTCPProductionScopeIdentity
	}{
		{name: "invalid-kind", scope: func() fakeTCPProductionScopeIdentity {
			scope := filesystem
			scope.objectKind = fakeTCPProductionObjectScopeInvalid
			return scope
		}()},
		{name: "invalid-embedded-source", scope: func() fakeTCPProductionScopeIdentity {
			scope := embedded
			scope.objectPath = "/object.o"
			return scope
		}()},
		{name: "relative-object", scope: func() fakeTCPProductionScopeIdentity {
			scope := filesystem
			scope.objectPath = "object.o"
			return scope
		}()},
		{name: "relative-pin", scope: func() fakeTCPProductionScopeIdentity {
			scope := filesystem
			scope.pinPath = "pins"
			return scope
		}()},
		{name: "relative-lifecycle", scope: func() fakeTCPProductionScopeIdentity {
			scope := filesystem
			scope.lifecyclePath = "daemon.lease"
			return scope
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.scope.validate(); err == nil {
				t.Fatalf("invalid scope validated: %#v", test.scope)
			}
		})
	}
}
