package guard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/syx0310/wg-mix-ebpf/internal/attachstate"
)

type secureStateDirectory struct {
	path       string
	file       *os.File
	chain      []*os.File
	components []string
	device     uint64
	inode      uint64
}

func openSecureStateDirectory(configured string, create bool) (*secureStateDirectory, error) {
	path := attachstate.StateDir(configured)
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("guard state directory must be absolute: %s", path)
	}
	rawComponents := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range rawComponents {
		if component == "." || component == ".." {
			return nil, fmt.Errorf("guard state directory has an unsafe component: %s", path)
		}
	}
	cleaned := filepath.Clean(path)
	if cleaned != path {
		return nil, fmt.Errorf("guard state directory must use its canonical lexical form: %s", path)
	}
	path = cleaned
	if path == string(filepath.Separator) {
		return nil, errors.New("guard state directory must not be the filesystem root")
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))

	root, err := guardOpenDirectoryPath(string(filepath.Separator))
	if err != nil {
		return nil, fmt.Errorf("open filesystem root for guard state traversal: %w", err)
	}
	chain := []*os.File{root}
	closeChain := func() {
		for index := len(chain) - 1; index >= 0; index-- {
			_ = chain[index].Close()
		}
	}
	rootInfo, err := root.Stat()
	if err != nil {
		closeChain()
		return nil, fmt.Errorf("inspect filesystem root for guard state traversal: %w", err)
	}
	if err := validateGuardAncestorDirectory(string(filepath.Separator), rootInfo); err != nil {
		closeChain()
		return nil, err
	}
	currentPath := string(filepath.Separator)
	for index, component := range components {
		if component == "" {
			closeChain()
			return nil, fmt.Errorf("guard state directory has an unsafe component: %s", path)
		}
		parent := chain[len(chain)-1]
		next, openErr := guardOpenDirectoryAt(parent, component)
		if errors.Is(openErr, os.ErrNotExist) && index != len(components)-1 {
			closeChain()
			return nil, fmt.Errorf(
				"guard state intermediate component %s is missing; ownership absence cannot be proven",
				filepath.Join(currentPath, component),
			)
		}
		if errors.Is(openErr, os.ErrNotExist) && create && index == len(components)-1 {
			if mkdirErr := guardMkdirDirectoryAt(parent, component, 0o755); mkdirErr != nil &&
				!errors.Is(mkdirErr, os.ErrExist) {
				closeChain()
				return nil, fmt.Errorf("create guard state directory %s: %w", path, mkdirErr)
			}
			next, openErr = guardOpenDirectoryAt(parent, component)
		}
		if openErr != nil {
			closeChain()
			return nil, fmt.Errorf(
				"open guard state component %s without following links: %w",
				filepath.Join(currentPath, component),
				openErr,
			)
		}
		if index != len(components)-1 {
			info, statErr := next.Stat()
			if statErr != nil {
				_ = next.Close()
				closeChain()
				return nil, fmt.Errorf(
					"inspect guard state ancestor %s: %w",
					filepath.Join(currentPath, component),
					statErr,
				)
			}
			if err := validateGuardAncestorDirectory(filepath.Join(currentPath, component), info); err != nil {
				_ = next.Close()
				closeChain()
				return nil, err
			}
		}
		chain = append(chain, next)
		currentPath = filepath.Join(currentPath, component)
	}

	final := chain[len(chain)-1]
	info, err := final.Stat()
	if err != nil {
		closeChain()
		return nil, fmt.Errorf("inspect guard state directory %s: %w", path, err)
	}
	if err := validateGuardStateDirectory(path, info); err != nil {
		closeChain()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		closeChain()
		return nil, fmt.Errorf("read guard state directory identity for %s", path)
	}
	directory := &secureStateDirectory{
		path:       path,
		file:       final,
		chain:      chain,
		components: components,
		device:     uint64(stat.Dev),
		inode:      uint64(stat.Ino),
	}
	if err := directory.validatePath(); err != nil {
		_ = directory.close()
		return nil, err
	}
	return directory, nil
}

func validateGuardStateDirectory(path string, info os.FileInfo) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("guard state path %s is not a real directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("guard state directory %s mode %04o is group/other writable", path, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read guard state directory ownership for %s", path)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf(
			"guard state directory %s uid %d does not match effective uid %d",
			path,
			stat.Uid,
			os.Geteuid(),
		)
	}
	return nil
}

func validateGuardAncestorDirectory(path string, info os.FileInfo) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("guard state ancestor %s is not a real directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read guard state ancestor ownership for %s", path)
	}
	owner := int(stat.Uid)
	if owner != 0 && owner != os.Geteuid() {
		return fmt.Errorf(
			"guard state ancestor %s uid %d is neither root nor effective uid %d",
			path,
			stat.Uid,
			os.Geteuid(),
		)
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf(
			"guard state ancestor %s mode %04o is writable without sticky rename protection",
			path,
			info.Mode().Perm(),
		)
	}
	return nil
}

func (d *secureStateDirectory) validatePath() error {
	if d == nil || d.file == nil || len(d.chain) != len(d.components)+1 {
		return errors.New("guard state directory is closed or incomplete")
	}
	rootInfo, err := d.chain[0].Stat()
	if err != nil {
		return fmt.Errorf("inspect anchored filesystem root: %w", err)
	}
	if err := validateGuardAncestorDirectory(string(filepath.Separator), rootInfo); err != nil {
		return err
	}
	for index, component := range d.components {
		current, err := guardOpenDirectoryAt(d.chain[index], component)
		if err != nil {
			return fmt.Errorf("revalidate guard state component %s: %w", component, err)
		}
		currentInfo, statErr := current.Stat()
		closeErr := current.Close()
		if statErr != nil {
			return fmt.Errorf("inspect revalidated guard state component %s: %w", component, statErr)
		}
		expectedInfo, err := d.chain[index+1].Stat()
		if err != nil {
			return fmt.Errorf("inspect anchored guard state component %s: %w", component, err)
		}
		if !os.SameFile(currentInfo, expectedInfo) {
			return fmt.Errorf("guard state component %s changed after descriptor anchoring", component)
		}
		if index+1 != len(d.chain)-1 {
			if err := validateGuardAncestorDirectory(component, expectedInfo); err != nil {
				return err
			}
		}
		if closeErr != nil {
			return fmt.Errorf("close revalidated guard state component %s: %w", component, closeErr)
		}
	}
	info, err := d.file.Stat()
	if err != nil {
		return fmt.Errorf("inspect anchored guard state directory %s: %w", d.path, err)
	}
	if err := validateGuardStateDirectory(d.path, info); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read anchored guard state directory identity for %s", d.path)
	}
	if uint64(stat.Dev) != d.device || uint64(stat.Ino) != d.inode {
		return fmt.Errorf("anchored guard state directory %s changed identity", d.path)
	}
	return nil
}

func (d *secureStateDirectory) close() error {
	if d == nil {
		return nil
	}
	var firstErr error
	for index := len(d.chain) - 1; index >= 0; index-- {
		if err := d.chain[index].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	d.file = nil
	d.chain = nil
	return firstErr
}

func (d *secureStateDirectory) sync() error {
	if d == nil || d.file == nil {
		return errors.New("guard state directory is closed")
	}
	return d.file.Sync()
}

func guardNamedFileMatches(parent *os.File, name string, expected *os.File) (bool, error) {
	current, err := guardOpenReadFileAt(parent, name)
	if err != nil {
		return false, err
	}
	defer current.Close()
	currentInfo, err := current.Stat()
	if err != nil {
		return false, err
	}
	expectedInfo, err := expected.Stat()
	if err != nil {
		return false, err
	}
	return os.SameFile(currentInfo, expectedInfo), nil
}
