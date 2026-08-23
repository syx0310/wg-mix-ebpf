//go:build darwin

package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinObjectBoundPublicationUsesExclusiveNamedFallback(t *testing.T) {
	parentPath := filepath.Join(t.TempDir(), "publication-parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, exists, err := openDeclaredArtifactParent(parentPath, parentPath)
	if err != nil || !exists {
		t.Fatalf("open publication parent: exists=%t err=%v", exists, err)
	}
	defer parent.close()

	finalPath := filepath.Join(parentPath, "artifact")
	namedStageObserved := false
	result, err := publishObjectBoundFreshFile(objectBoundFreshFileSpec{
		parent:  parent,
		name:    filepath.Base(finalPath),
		path:    finalPath,
		kind:    "test artifact",
		mode:    0o600,
		content: []byte("owned\n"),
		beforePublish: func(state objectBoundFreshFileHookState) error {
			namedStageObserved = state.NamedStage != ""
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := result.file.Close(); err != nil {
		t.Fatal(err)
	}
	if !namedStageObserved {
		t.Fatal("Darwin publication did not use the exclusive named fallback")
	}
	if data, err := os.ReadFile(finalPath); err != nil || string(data) != "owned\n" {
		t.Fatalf("published artifact data=%q err=%v", data, err)
	}
}
