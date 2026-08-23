package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// This source contract runs on every host OS. The behavior it protects lives
// behind //go:build linux, so a Darwin test run must not be able to silently
// cross-compile a merge that dropped the pre-mutation production defenses.
func TestLinuxLoaderRetainsGateManifestAndDualBackendCallers(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "loader_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	newLoader := linuxLoaderFunction(t, file, "NewLoaderWithOptions", false)
	assertLinuxLoaderCallOrder(t, newLoader,
		"objectPathFromEnv",
		"pinPathFromEnv",
		"newFakeTCPProductionLoader",
	)

	loadObject := linuxLoaderFunction(t, file, "LoadObjectTestIdentity", false)
	assertLinuxLoaderCallOrder(t, loadObject,
		"loadCollectionSpec",
		"validateBaselineLoaderCollectionSpec",
		"removeMemlockLimit",
		"NewCollection",
	)

	apply := linuxLoaderFunction(t, file, "Apply", true)
	assertLinuxLoaderCallOrder(t, apply,
		"preflightProductionUnderlayParsers",
		"preflightFakeTCPKernelRequirements",
		"durableAutoBackend",
		"preflightExactTCXCapabilities",
		"applyExactTCX",
		"applyClassicTC",
	)

	exactApply := linuxLoaderFunction(t, file, "applyExactTCX", true)
	assertLinuxLoaderCallOrder(t, exactApply,
		"preflightFakeTCPKernelRequirements",
		"validatePinPath",
		"loadCollectionSpec",
		"validateBaselineLoaderCollectionSpec",
		"validateAndSetPinnedMaps",
		"removeMemlockLimit",
	)

	classicFile, err := parser.ParseFile(fileSet, "loader_classic_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	classicApply := linuxLoaderFunction(t, classicFile, "applyClassicTC", true)
	assertLinuxLoaderCallOrder(t, classicApply,
		"preflightFakeTCPKernelRequirements",
		"validateTCRuntime",
		"validatePinPath",
		"loadCollectionSpec",
		"validateBaselineLoaderCollectionSpec",
		"validateAndSetPinnedMaps",
		"removeMemlockLimit",
		"prepareTCAttachPlan",
	)
}

func linuxLoaderFunction(
	t *testing.T,
	file *ast.File,
	name string,
	method bool,
) *ast.FuncDecl {
	t.Helper()
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != name || (function.Recv != nil) != method {
			continue
		}
		return function
	}
	t.Fatalf("loader_linux.go has no expected function %s", name)
	return nil
}

func assertLinuxLoaderCallOrder(
	t *testing.T,
	function *ast.FuncDecl,
	names ...string,
) {
	t.Helper()
	positions := make(map[string]token.Pos, len(names))
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch callee := call.Fun.(type) {
		case *ast.Ident:
			name = callee.Name
		case *ast.SelectorExpr:
			name = callee.Sel.Name
		}
		if _, wanted := positions[name]; wanted || name == "" {
			return true
		}
		for _, candidate := range names {
			if name == candidate {
				positions[name] = call.Pos()
				break
			}
		}
		return true
	})

	var previous token.Pos
	for _, name := range names {
		position := positions[name]
		if position == token.NoPos {
			t.Fatalf("%s has no call to %s", function.Name.Name, name)
		}
		if previous != token.NoPos && position <= previous {
			t.Fatalf("%s does not call %s in the required pre-mutation order", function.Name.Name, name)
		}
		previous = position
	}
}
