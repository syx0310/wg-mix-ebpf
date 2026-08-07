//go:build linux

package dataplane

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeExperimentalCollection struct {
	closed *bool
	order  *[]string
}

func (collection *fakeExperimentalCollection) Close() {
	*collection.closed = true
	*collection.order = append(*collection.order, "close")
}

func TestExperimentalVerifierLoadValidatesBeforeKernelLoadAndCloses(t *testing.T) {
	spec := canonicalExperimentalCollectionSpec()
	var order []string
	closed := false
	err := loadExperimentalFakeTCPCollection(
		spec,
		"/reviewed/experimental.o",
		func() error {
			order = append(order, "remove-memlock")
			return nil
		},
		func(got *ebpf.CollectionSpec) (experimentalCollectionCloser, error) {
			order = append(order, "new-collection")
			if got != spec {
				t.Fatal("loader did not receive the manifest-validated collection spec")
			}
			for _, descriptor := range experimentalMapDescriptors() {
				if got.Maps[descriptor.name] == nil {
					t.Fatalf("loader spec is missing map %q", descriptor.name)
				}
			}
			for _, descriptor := range experimentalProgramDescriptors() {
				if got.Programs[descriptor.name] == nil {
					t.Fatalf("loader spec is missing program %q", descriptor.name)
				}
			}
			return &fakeExperimentalCollection{closed: &closed, order: &order}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("verifier-loaded collection was not closed")
	}
	if got, want := strings.Join(order, ","), "remove-memlock,new-collection,close"; got != want {
		t.Fatalf("load order = %q, want %q", got, want)
	}
}

func TestExperimentalVerifierLoadFailsBeforeKernelMutationOnManifestDrift(t *testing.T) {
	for _, mutate := range []func(*ebpf.CollectionSpec){
		func(spec *ebpf.CollectionSpec) {
			spec.Maps["faketcp_session_map"].Pinning = ebpf.PinByName
		},
		func(spec *ebpf.CollectionSpec) {
			spec.Maps["unknown"] = &ebpf.MapSpec{Name: "unknown"}
		},
		func(spec *ebpf.CollectionSpec) {
			spec.Programs["unknown"] = &ebpf.ProgramSpec{Name: "unknown"}
		},
	} {
		spec := canonicalExperimentalCollectionSpec()
		mutate(spec)
		memlockCalls := 0
		collectionCalls := 0
		err := loadExperimentalFakeTCPCollection(
			spec,
			"/reviewed/experimental.o",
			func() error {
				memlockCalls++
				return nil
			},
			func(*ebpf.CollectionSpec) (experimentalCollectionCloser, error) {
				collectionCalls++
				return nil, errors.New("must not run")
			},
		)
		if err == nil || !strings.Contains(err.Error(), "validate experimental FakeTCP BPF object") {
			t.Fatalf("manifest drift error = %v", err)
		}
		if memlockCalls != 0 || collectionCalls != 0 {
			t.Fatalf("manifest drift reached kernel steps: memlock=%d collection=%d", memlockCalls, collectionCalls)
		}
	}
}

func TestExperimentalVerifierLoadStopsAfterMemlockFailure(t *testing.T) {
	wantErr := errors.New("memlock unavailable")
	collectionCalls := 0
	err := loadExperimentalFakeTCPCollection(
		canonicalExperimentalCollectionSpec(),
		"/reviewed/experimental.o",
		func() error { return wantErr },
		func(*ebpf.CollectionSpec) (experimentalCollectionCloser, error) {
			collectionCalls++
			return nil, nil
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if collectionCalls != 0 {
		t.Fatalf("collection loader ran %d times after memlock failure", collectionCalls)
	}
}

func TestExperimentalVerifierLoadFailsClosedOnNilCollection(t *testing.T) {
	err := loadExperimentalFakeTCPCollection(
		canonicalExperimentalCollectionSpec(),
		"/reviewed/experimental.o",
		func() error { return nil },
		func(*ebpf.CollectionSpec) (experimentalCollectionCloser, error) {
			return nil, nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "loader returned nil collection") {
		t.Fatalf("nil collection error = %v", err)
	}
}

func TestExperimentalVerifierLoaderRejectsEmptyPathBeforeEnvironmentFallback(t *testing.T) {
	t.Setenv(EnvObjectPath, "/must/not/be/used.o")
	for _, path := range []string{"", "\t\n"} {
		_, err := LoadExperimentalFakeTCPObjectTestIdentity(t.Context(), path)
		if err == nil || !strings.Contains(err.Error(), "explicit non-empty object path") {
			t.Fatalf("path=%q error=%v", path, err)
		}
	}
}

func TestExperimentalVerifierLoaderSourceHasNoAttachPinOrMapMutationCalls(t *testing.T) {
	file, err := parser.ParseFile(
		token.NewFileSet(),
		"experimental_load_linux.go",
		nil,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	newCollectionCalls := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		callName := ""
		switch function := call.Fun.(type) {
		case *ast.Ident:
			callName = function.Name
		case *ast.SelectorExpr:
			callName = function.Sel.Name
			if packageName, ok := function.X.(*ast.Ident); ok &&
				packageName.Name == "ebpf" && callName == "NewCollection" {
				newCollectionCalls++
			}
		}
		lower := strings.ToLower(callName)
		if strings.Contains(lower, "attach") || strings.Contains(lower, "pin") ||
			strings.Contains(lower, "populate") || callName == "Update" ||
			callName == "Put" || callName == "Delete" {
			t.Errorf("load-only source contains forbidden kernel mutation call %q", callName)
		}
		return true
	})
	if newCollectionCalls != 1 {
		t.Fatalf("ebpf.NewCollection calls = %d, want exactly 1", newCollectionCalls)
	}
}
