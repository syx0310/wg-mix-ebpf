package faketcp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

func TestLinuxRuntimeIdentityHasNoExportedRawSeedFunction(t *testing.T) {
	packages, err := parser.ParseDir(
		token.NewFileSet(), ".", func(info fs.FileInfo) bool {
			return !strings.HasSuffix(info.Name(), "_test.go")
		}, parser.SkipObjectResolution,
	)
	if err != nil {
		t.Fatal(err)
	}
	seedCalls := 0
	preCommitCalls := 0
	for _, file := range packages["faketcp"].Files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if ast.IsExported(function.Name.Name) &&
				(strings.Contains(function.Name.Name, "Seed") ||
					strings.Contains(function.Name.Name, "PreCommit")) {
				t.Fatalf("raw or repeatable Linux seed API remains exported: %s", function.Name.Name)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			function, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch function.Name {
			case "seedLinuxRuntimeIdentity":
				seedCalls++
			case "newLinuxRuntimeIdentityPreCommit":
				preCommitCalls++
			}
			return true
		})
	}
	if seedCalls != 1 || preCommitCalls != 1 {
		t.Fatalf(
			"Linux seed path bypassed once-only capability: seed calls=%d pre-commit calls=%d",
			seedCalls, preCommitCalls,
		)
	}
}
