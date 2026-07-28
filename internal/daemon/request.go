package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"golang.org/x/sys/unix"
)

const (
	requestProtocolVersion = 1
	requestsDirName        = "requests"
	acksDirName            = "acks"
	maxPendingRequestFiles = 256
	maxRetainedAckFiles    = 512
	maxControlFileBytes    = 1 << 20
	ackErrorDaemonChanged  = "daemon_instance_changed"
)

type daemonRequest struct {
	Version            int       `json:"version"`
	ID                 string    `json:"id"`
	Kind               string    `json:"kind"`
	ExpectedInstanceID string    `json:"expected_instance_id"`
	ExpectedConfigPath string    `json:"expected_config_path,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
}

type requestAck struct {
	Version     int       `json:"version"`
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	CompletedAt time.Time `json:"completed_at"`
	Status      Status    `json:"status"`
	Error       string    `json:"error,omitempty"`
	ErrorCode   string    `json:"error_code,omitempty"`
}

type pendingRequest struct {
	request daemonRequest
	path    string
}

func ensureRequestDirs(runDir string) error {
	for _, name := range []string{requestsDirName, acksDirName} {
		path := filepath.Join(runDir, name)
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create daemon %s directory: %w", name, err)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect daemon %s directory: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("daemon %s path is not a real directory", name)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("secure daemon %s directory: %w", name, err)
		}
	}
	return nil
}

func enqueueRequest(
	ctx context.Context,
	runDir string,
	kind string,
	expectedConfigPath string,
	expectedInstanceID string,
) (daemonRequest, error) {
	id, err := newRequestID()
	if err != nil {
		return daemonRequest{}, err
	}
	request := daemonRequest{
		Version:            requestProtocolVersion,
		ID:                 id,
		Kind:               kind,
		ExpectedInstanceID: expectedInstanceID,
		ExpectedConfigPath: expectedConfigPath,
		CreatedAt:          time.Now(),
	}
	if err := ensureRequestDirs(runDir); err != nil {
		return daemonRequest{}, err
	}
	requestDir := filepath.Join(runDir, requestsDirName)
	if err := lockfile.WithLock(ctx, requestDir, func() error {
		count, err := countJSONFiles(requestDir)
		if err != nil {
			return fmt.Errorf("count queued daemon requests: %w", err)
		}
		if count >= maxPendingRequestFiles {
			return fmt.Errorf("daemon request queue is full (%d pending requests)", maxPendingRequestFiles)
		}
		return writeRequestFile(runDir, request)
	}); err != nil {
		return daemonRequest{}, err
	}
	return request, nil
}

func writeRequestFile(runDir string, request daemonRequest) error {
	if err := validateRequest(request); err != nil {
		return err
	}
	if err := ensureRequestDirs(runDir); err != nil {
		return err
	}
	path := requestPath(runDir, request.ID)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("daemon request %s already exists", request.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeJSONAtomic(filepath.Dir(path), filepath.Base(path), request); err != nil {
		return fmt.Errorf("write daemon %s request %s: %w", request.Kind, request.ID, err)
	}
	return nil
}

func pendingRequests(runDir string) ([]pendingRequest, error) {
	if err := ensureRequestDirs(runDir); err != nil {
		return nil, err
	}
	dir := filepath.Join(runDir, requestsDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read daemon request directory: %w", err)
	}
	pending := make([]pendingRequest, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		id := strings.TrimSuffix(entry.Name(), ".json")
		request, present, err := readPendingRequest(runDir, path, id)
		if err != nil {
			return nil, err
		}
		if present {
			pending = append(pending, request)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].request.CreatedAt.Equal(pending[j].request.CreatedAt) {
			return pending[i].request.ID < pending[j].request.ID
		}
		return pending[i].request.CreatedAt.Before(pending[j].request.CreatedAt)
	})
	return pending, nil
}

func readPendingRequest(runDir string, path string, id string) (pendingRequest, bool, error) {
	data, err := readRegularControlFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return pendingRequest{}, false, nil
	}
	if err != nil {
		return pendingRequest{}, false, fmt.Errorf("read daemon request %s: %w", id, err)
	}
	var request daemonRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return pendingRequest{}, false, fmt.Errorf("parse daemon request %s: %w", id, err)
	}
	if request.ID != id {
		return pendingRequest{}, false, fmt.Errorf("daemon request filename id %s does not match payload id %s", id, request.ID)
	}
	if err := validateRequest(request); err != nil {
		return pendingRequest{}, false, fmt.Errorf("validate daemon request %s: %w", id, err)
	}
	if ack, err := readRequestAck(runDir, id); err == nil {
		if err := validateAckForRequest(ack, request); err != nil {
			return pendingRequest{}, false, fmt.Errorf("validate existing daemon request ack %s: %w", id, err)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return pendingRequest{}, false, fmt.Errorf("remove already-acknowledged request %s: %w", id, err)
		}
		return pendingRequest{}, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return pendingRequest{}, false, fmt.Errorf("validate existing daemon request ack %s: %w", id, err)
	}
	return pendingRequest{request: request, path: path}, true, nil
}

func acknowledgeRequest(runDir string, pending pendingRequest, status Status, requestErr error) error {
	ack := requestAck{
		Version:     requestProtocolVersion,
		ID:          pending.request.ID,
		Kind:        pending.request.Kind,
		CompletedAt: time.Now(),
		Status:      status,
	}
	if requestErr != nil {
		ack.Error = requestErr.Error()
		if errors.Is(requestErr, ErrDaemonNotRunning) {
			ack.ErrorCode = ackErrorDaemonChanged
		}
	}
	path := ackPath(runDir, pending.request.ID)
	if err := writeJSONAtomic(filepath.Dir(path), filepath.Base(path), ack); err != nil {
		return fmt.Errorf("write daemon request ack %s: %w", pending.request.ID, err)
	}
	if err := os.Remove(pending.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove completed daemon request %s: %w", pending.request.ID, err)
	}
	return nil
}

func pruneAcknowledgements(runDir string) error {
	dir := filepath.Join(runDir, acksDirName)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read daemon ack directory: %w", err)
	}
	type candidate struct {
		name    string
		id      string
		modTime time.Time
	}
	candidates := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect daemon ack %s: %w", entry.Name(), err)
		}
		candidates = append(candidates, candidate{
			name:    entry.Name(),
			id:      strings.TrimSuffix(entry.Name(), ".json"),
			modTime: info.ModTime(),
		})
	}
	if len(candidates) <= maxRetainedAckFiles {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modTime.Equal(candidates[j].modTime) {
			return candidates[i].name < candidates[j].name
		}
		return candidates[i].modTime.Before(candidates[j].modTime)
	})
	remaining := len(candidates)
	for _, ack := range candidates {
		if remaining <= maxRetainedAckFiles {
			return nil
		}
		if _, err := os.Lstat(requestPath(runDir, ack.id)); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect request paired with daemon ack %s: %w", ack.id, err)
		}
		if err := os.Remove(filepath.Join(dir, ack.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("prune daemon ack %s: %w", ack.id, err)
		}
		remaining--
	}
	if remaining > maxRetainedAckFiles {
		return fmt.Errorf(
			"cannot bound daemon ack history to %d files: %d acknowledgements still have paired requests",
			maxRetainedAckFiles,
			remaining,
		)
	}
	return nil
}

func consumeAckIfRequestRemoved(runDir string, id string) (bool, error) {
	if _, err := os.Lstat(requestPath(runDir, id)); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.Remove(ackPath(runDir, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return true, nil
}

func readRequestAck(runDir string, id string) (*requestAck, error) {
	data, err := readRegularControlFile(ackPath(runDir, id))
	if err != nil {
		return nil, err
	}
	var ack requestAck
	if err := json.Unmarshal(data, &ack); err != nil {
		return nil, err
	}
	if ack.Version != requestProtocolVersion || ack.ID != id {
		return nil, fmt.Errorf("invalid daemon request ack for %s", id)
	}
	return &ack, nil
}

func validateAckForRequest(ack *requestAck, request daemonRequest) error {
	if ack.Kind != request.Kind {
		return fmt.Errorf("ack kind %q does not match request kind %q", ack.Kind, request.Kind)
	}
	switch ack.ErrorCode {
	case "":
		if ack.Status.InstanceID != request.ExpectedInstanceID {
			return fmt.Errorf(
				"ack daemon instance %q does not match request instance %q",
				ack.Status.InstanceID,
				request.ExpectedInstanceID,
			)
		}
	case ackErrorDaemonChanged:
		if ack.Error == "" {
			return errors.New("daemon-instance-changed ack is missing an error")
		}
		if !validRequestID(ack.Status.InstanceID) {
			return fmt.Errorf("daemon-instance-changed ack has invalid daemon instance %q", ack.Status.InstanceID)
		}
		if ack.Status.InstanceID == request.ExpectedInstanceID {
			return fmt.Errorf("daemon-instance-changed ack was written by request instance %q", ack.Status.InstanceID)
		}
	default:
		return fmt.Errorf("unsupported ack error code %q", ack.ErrorCode)
	}
	return nil
}

func readRegularControlFile(path string) ([]byte, error) {
	file, err := openControlFileNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readOpenedRegularControlFile(file)
}

func openControlFileNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("refuse symbolic-link control file: %w", err)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func readOpenedRegularControlFile(file *os.File) ([]byte, error) {
	fd := int(file.Fd())
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("control path is not a regular file")
	}
	// A zero link count means the pathname was unlinked or atomically replaced
	// after the no-follow open. The descriptor still identifies the regular
	// inode and is safe to read; only multiply-linked control files are unsafe.
	if stat.Nlink > 1 {
		return nil, fmt.Errorf("refuse control file with %d links", stat.Nlink)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxControlFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxControlFileBytes {
		return nil, fmt.Errorf("control file exceeds %d bytes", maxControlFileBytes)
	}
	return data, nil
}

func countJSONFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			count++
		}
	}
	return count, nil
}

func validateRequest(request daemonRequest) error {
	if request.Version != requestProtocolVersion {
		return fmt.Errorf("unsupported request protocol version %d", request.Version)
	}
	if !validRequestID(request.ID) {
		return fmt.Errorf("invalid request id %q", request.ID)
	}
	if !validRequestID(request.ExpectedInstanceID) {
		return fmt.Errorf("invalid expected daemon instance id %q", request.ExpectedInstanceID)
	}
	switch request.Kind {
	case "reload", "stop":
	default:
		return fmt.Errorf("invalid request kind %q", request.Kind)
	}
	if request.CreatedAt.IsZero() {
		return errors.New("request creation time is required")
	}
	return nil
}

func validRequestID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func newRequestID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate daemon request id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func requestPath(runDir string, id string) string {
	return filepath.Join(runDir, requestsDirName, id+".json")
}

func ackPath(runDir string, id string) string {
	return filepath.Join(runDir, acksDirName, id+".json")
}

func writeJSONAtomic(dir string, name string, value any) error {
	return writeJSONAtomicMode(dir, name, value, 0o600)
}

func writeJSONAtomicMode(dir string, name string, value any, mode os.FileMode) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filepath.Join(dir, name))
}
