package install

import (
	"fmt"
	"path/filepath"
	"strings"
)

func refuseRetainedInstallTemporary(
	parent *cleanupDirFD,
	prefix string,
	kind string,
) error {
	entries, err := cleanupReadDir(parent)
	if err != nil {
		return fmt.Errorf("inspect %s directory for retained temporary names: %w", kind, err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		return fmt.Errorf(
			"refuse to create another temporary %s while retained name %s awaits "+
				"manual identity inspection",
			kind,
			filepath.Join(parent.path, entry.Name()),
		)
	}
	return nil
}
