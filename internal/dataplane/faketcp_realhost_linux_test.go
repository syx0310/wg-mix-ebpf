//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	ciliumlink "github.com/cilium/ebpf/link"
	"github.com/syx0310/wg-mix-ebpf/internal/abi"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
	"github.com/syx0310/wg-mix-ebpf/internal/faketcp"
	"github.com/syx0310/wg-mix-ebpf/internal/lockfile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const fakeTCPRealHostObjectSizeLimit = 128 << 20

type fakeTCPRealHostPrepared struct {
	contract         fakeTCPRealHostContract
	experimentalSpec *ebpf.CollectionSpec
	baselineSpec     *ebpf.CollectionSpec
}

type fakeTCPRealHostTCXProgram struct {
	programID uint32
	linkID    uint32
}

type fakeTCPRealHostTCXSlot struct {
	ifindex int
	attach  ebpf.AttachType
}

type fakeTCPRealHostKernelSnapshot struct {
	xdp map[int]fakeTCPXDPProbe
	tcx map[fakeTCPRealHostTCXSlot][]fakeTCPRealHostTCXProgram
}

type fakeTCPRealHostSlowPath struct {
	started   chan struct{}
	stop      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

func newFakeTCPRealHostSlowPath() *fakeTCPRealHostSlowPath {
	return &fakeTCPRealHostSlowPath{
		started: make(chan struct{}),
		stop:    make(chan struct{}),
	}
}

func (slowPath *fakeTCPRealHostSlowPath) Run(ctx context.Context) error {
	if slowPath == nil || ctx == nil {
		return errors.New("FakeTCP real-host slow path is unavailable")
	}
	slowPath.startOnce.Do(func() { close(slowPath.started) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-slowPath.stop:
		return nil
	}
}

func (slowPath *fakeTCPRealHostSlowPath) RequestStop() error {
	if slowPath == nil {
		return errors.New("FakeTCP real-host slow path is unavailable")
	}
	slowPath.stopOnce.Do(func() { close(slowPath.stop) })
	return nil
}

func (slowPath *fakeTCPRealHostSlowPath) Close() error {
	return slowPath.RequestStop()
}

type fakeTCPRealHostGenerationIsolation struct {
	mu         sync.Mutex
	owner      *experimentalCollectionOwner
	generation uint64
	ifindexes  []int
}

func (isolation *fakeTCPRealHostGenerationIsolation) bind(owner *experimentalCollectionOwner) error {
	if isolation == nil || owner == nil {
		return errors.New("bind FakeTCP real-host generation isolation: owner is nil")
	}
	isolation.mu.Lock()
	defer isolation.mu.Unlock()
	if isolation.owner != nil && isolation.owner != owner {
		return errors.New("bind FakeTCP real-host generation isolation: owner already bound")
	}
	isolation.owner = owner
	return nil
}

func (isolation *fakeTCPRealHostGenerationIsolation) AssertInactive(
	ctx context.Context,
	generation uint64,
) error {
	if ctx == nil {
		return errors.New("prove FakeTCP real-host generation inactive: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if isolation == nil || generation == 0 || generation != isolation.generation {
		return errors.New("prove FakeTCP real-host generation inactive: generation identity mismatch")
	}
	owner := isolation.boundOwner()
	if owner == nil {
		return errors.New("prove FakeTCP real-host generation inactive: collection owner is unbound")
	}
	controlMap, err := owner.mapResource("control_map")
	if err != nil {
		return err
	}
	var observed abi.ControlValue
	if err := controlMap.Lookup(abi.ControlKeyGlobal, &observed); err != nil {
		return fmt.Errorf("prove FakeTCP real-host generation inactive: read selector: %w", err)
	}
	if observed != (abi.ControlValue{}) {
		return fmt.Errorf("prove FakeTCP real-host generation inactive: selector is %#v", observed)
	}
	return nil
}

func (isolation *fakeTCPRealHostGenerationIsolation) Quiesce(
	ctx context.Context,
	generation uint64,
) error {
	if err := isolation.AssertInactive(ctx, generation); err != nil {
		return err
	}
	for _, ifindex := range isolation.ifindexes {
		probe, err := probeLiveFakeTCPXDP(ifindex)
		if err != nil {
			return fmt.Errorf("quiesce FakeTCP real-host generation: probe XDP ifindex %d: %w", ifindex, err)
		}
		if probe.Attached || probe.ProgramID != 0 {
			return fmt.Errorf("quiesce FakeTCP real-host generation: XDP remains on ifindex %d", ifindex)
		}
		for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
			programs, err := queryFakeTCPRealHostTCX(ifindex, attach)
			if err != nil {
				return err
			}
			if len(programs) != 0 {
				return fmt.Errorf(
					"quiesce FakeTCP real-host generation: TCX %s remains on ifindex %d",
					attach,
					ifindex,
				)
			}
		}
	}
	return nil
}

func (isolation *fakeTCPRealHostGenerationIsolation) boundOwner() *experimentalCollectionOwner {
	if isolation == nil {
		return nil
	}
	isolation.mu.Lock()
	defer isolation.mu.Unlock()
	return isolation.owner
}

// TestExperimentalFakeTCPRealHostLifecycleIntegration is an explicitly gated
// kernel test. It owns no persistent pins: the only mutations are exact XDP
// and TCX links on the controller-created veth pair, and Close acts only on
// the link FDs returned by this runtime.
func TestExperimentalFakeTCPRealHostLifecycleIntegration(t *testing.T) {
	prepared := requireFakeTCPRealHostPrepared(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	runtime, slowPath := buildFakeTCPRealHostRuntime(ctx, t, prepared, false, "lifecycle")
	closed := false
	defer func() {
		if !closed {
			if err := runtime.Close(); err != nil {
				t.Errorf("close exact FakeTCP real-host runtime after failure: %v", err)
			}
		}
	}()
	assertFakeTCPRealHostRuntimeAttached(t, prepared.contract)

	handles, err := runtime.Handles()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Generation() == 0 || handles.Generation() != runtime.Generation() ||
		handles.Identity() != runtime.Identity() || handles.SessionStore() == nil {
		t.Fatalf("runtime identity=%#v generation=%d handles identity=%#v generation=%d store=%v",
			runtime.Identity(), runtime.Generation(), handles.Identity(), handles.Generation(), handles.SessionStore())
	}
	runErr := make(chan error, 1)
	go func() { runErr <- runtime.Run(ctx) }()
	select {
	case <-slowPath.started:
	case <-time.After(5 * time.Second):
		t.Fatal("FakeTCP real-host runtime slow path did not start")
	}
	if err := runtime.RequestStop(); err != nil {
		t.Fatalf("request FakeTCP real-host runtime stop: %v", err)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run FakeTCP real-host runtime: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FakeTCP real-host runtime did not stop")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close FakeTCP real-host runtime: %v", err)
	}
	closed = true
	assertFakeTCPRealHostKernelEmpty(t, prepared.contract)
	t.Logf("FAKETCP_REALHOST_LIFECYCLE_COMPLETE run_id=%s restored=1", prepared.contract.runID)
}

// TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration sends one
// materialized CHECKSUM_NONE Ethernet/IPv4/UDP frame through the exact veth
// pair. The AF_PACKET observation must equal one of the two reviewed receive
// images (post-XDP encrypted UDP or post-TCX restored UDP), and the FakeTCP,
// core, and XOR success counters must each advance exactly once with no error
// growth. Together those oracles cover header conversion, type-word mapping,
// XOR, inverse XOR, inverse type-word mapping, and checksum restoration.
func TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration(t *testing.T) {
	prepared := requireFakeTCPRealHostPrepared(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	runtime, _ := buildFakeTCPRealHostRuntime(ctx, t, prepared, true, "composition")
	closed := false
	defer func() {
		if !closed {
			if err := runtime.Close(); err != nil {
				t.Errorf("close exact FakeTCP composition runtime after failure: %v", err)
			}
		}
	}()
	assertFakeTCPRealHostRuntimeAttached(t, prepared.contract)

	handles, err := runtime.Handles()
	if err != nil {
		t.Fatal(err)
	}
	installFakeTCPRealHostSessions(t, handles, runtime.Generation(), prepared.contract)
	beforeEgress := readFakeTCPRealHostStat(t, runtime, 0)
	beforeIngress := readFakeTCPRealHostStat(t, runtime, 1)
	beforeCoreEgress := readFakeTCPRealHostCoreStat(t, runtime, 0)
	beforeCoreIngress := readFakeTCPRealHostCoreStat(t, runtime, 6)
	beforeXOREgress := readFakeTCPRealHostCoreStat(t, runtime, 24)
	beforeXORIngress := readFakeTCPRealHostCoreStat(t, runtime, 25)
	fakeErrorsBefore := readFakeTCPRealHostStats(t, runtime, "faketcp_stats_map", 13)
	coreErrorsBefore := readFakeTCPRealHostStats(t, runtime, "stats_map", 36)

	local, err := netlink.LinkByIndex(prepared.contract.ifindex)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByIndex(prepared.contract.peerIfindex)
	if err != nil {
		t.Fatal(err)
	}
	packet, originalPayload := buildFakeTCPProbeUDPPacket(t, 31001, 31002, 65)
	copy(packet[0:6], peer.Attrs().HardwareAddr)
	copy(packet[6:12], local.Attrs().HardwareAddr)

	receiver := openFakeTCPRealHostPacketSocket(t, prepared.contract.peerIfindex)
	defer closeFakeTCPRealHostFD(t, receiver, "peer packet socket")
	sender := openFakeTCPRealHostPacketSocket(t, prepared.contract.ifindex)
	defer closeFakeTCPRealHostFD(t, sender, "sender packet socket")
	if err := unix.Sendto(sender, packet, 0, &unix.SockaddrLinklayer{
		Protocol: fakeTCPRealHostHTONS(unix.ETH_P_IP),
		Ifindex:  prepared.contract.ifindex,
	}); err != nil {
		t.Fatalf("send run-owned veth frame: %v", err)
	}
	receiveCtx, stopReceive := context.WithTimeout(ctx, 10*time.Second)
	defer stopReceive()
	received, err := receiveFakeTCPRealHostUDPPacket(receiveCtx, receiver, 31001, 31002)
	if err != nil {
		t.Fatal(err)
	}
	const payloadOffset = 14 + 20 + 8
	if len(received) < payloadOffset+len(originalPayload) {
		t.Fatalf("FakeTCP+XOR+type-word observation is short: %d", len(received))
	}
	encryptedPayload := append([]byte(nil), originalPayload...)
	binary.LittleEndian.PutUint32(encryptedPayload[:4], 0x13dff06b)
	for index := range encryptedPayload {
		encryptedPayload[index] ^= byte(index*17 + 5)
	}
	observedPayload := received[payloadOffset : payloadOffset+len(originalPayload)]
	// AF_PACKET taps are kernel-order dependent relative to clsact ingress.
	// Seeing encryptedPayload proves the post-XDP/pre-TCX image; seeing the
	// original proves the post-TCX image. The four exact success counters below
	// are mandatory in either case and prove that both halves completed.
	if !bytes.Equal(observedPayload, encryptedPayload) && !bytes.Equal(observedPayload, originalPayload) {
		t.Fatalf("FakeTCP+XOR+type-word observation is neither reviewed pipeline image: got=%x encrypted=%x original=%x",
			observedPayload, encryptedPayload, originalPayload)
	}
	waitForFakeTCPRealHostStat(t, runtime, "stats_map", 25, beforeXORIngress+1)
	if after := readFakeTCPRealHostStat(t, runtime, 0); after != beforeEgress+1 {
		t.Fatalf("FakeTCP egress success delta=%d, want 1", after-beforeEgress)
	}
	if after := readFakeTCPRealHostStat(t, runtime, 1); after != beforeIngress+1 {
		t.Fatalf("FakeTCP ingress success delta=%d, want 1", after-beforeIngress)
	}
	for _, success := range []struct {
		name   string
		key    uint32
		before uint64
	}{
		{"core egress rewrite", 0, beforeCoreEgress},
		{"core ingress rewrite", 6, beforeCoreIngress},
		{"XOR egress", 24, beforeXOREgress},
		{"XOR ingress", 25, beforeXORIngress},
	} {
		after := readFakeTCPRealHostCoreStat(t, runtime, success.key)
		if after != success.before+1 {
			t.Fatalf("%s success delta=%d, want 1", success.name, after-success.before)
		}
	}
	fakeErrorsAfter := readFakeTCPRealHostStats(t, runtime, "faketcp_stats_map", 13)
	for key := 2; key < len(fakeErrorsAfter); key++ {
		if fakeErrorsAfter[key] != fakeErrorsBefore[key] {
			t.Fatalf("FakeTCP error stat %d delta=%d, want 0", key, fakeErrorsAfter[key]-fakeErrorsBefore[key])
		}
	}
	coreErrorsAfter := readFakeTCPRealHostStats(t, runtime, "stats_map", 36)
	for key := range coreErrorsAfter {
		if key == 0 || key == 6 || key == 24 || key == 25 {
			continue
		}
		if coreErrorsAfter[key] != coreErrorsBefore[key] {
			t.Fatalf("unexpected core stat %d delta=%d, want 0", key, coreErrorsAfter[key]-coreErrorsBefore[key])
		}
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("close FakeTCP composition runtime: %v", err)
	}
	closed = true
	assertFakeTCPRealHostKernelEmpty(t, prepared.contract)
	t.Logf("FAKETCP_REALHOST_COMPOSITION_COMPLETE run_id=%s restored=1", prepared.contract.runID)
}

// TestBaselineExperimentalRealHostMutualExclusionIntegration proves that an
// active experimental owner cannot be competed with through the production
// baseline loader. The baseline loader must reject FakeTCP at its hard gate
// before it opens an object, validates a pin path, or changes the exact XDP and
// TCX identities already owned by the experimental runtime.
func TestBaselineExperimentalRealHostMutualExclusionIntegration(t *testing.T) {
	prepared := requireFakeTCPRealHostPrepared(t)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	if err := validateBaselineCollectionSpec(prepared.experimentalSpec); err == nil {
		t.Fatal("experimental object unexpectedly passed the baseline manifest")
	}
	if err := validateExperimentalExtensionManifest(prepared.baselineSpec); err == nil {
		t.Fatal("baseline object unexpectedly passed the experimental manifest")
	}

	runtime, _ := buildFakeTCPRealHostRuntime(ctx, t, prepared, false, "mutual-exclusion")
	closed := false
	defer func() {
		if !closed {
			if err := runtime.Close(); err != nil {
				t.Errorf("close exact FakeTCP mutual-exclusion runtime after failure: %v", err)
			}
		}
	}()
	active := assertFakeTCPRealHostRuntimeAttached(t, prepared.contract)

	forbiddenPin := filepath.Join(
		prepared.contract.tempRoot,
		"faketcp-"+prepared.contract.runID+"-baseline-gate-pin",
	)
	if _, err := os.Lstat(forbiddenPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refuse baseline mutual-exclusion probe because path exists: %s: %v", forbiddenPin, err)
	}
	state := fakeTCPRealHostState(prepared.contract, runtime.Generation(), false)
	err := (LinuxLoader{
		ObjectPath: prepared.contract.baselineObject,
		PinPath:    forbiddenPin,
	}).Apply(ctx, state)
	if !errors.Is(err, ErrFakeTCPKernelGate) {
		t.Fatalf("baseline loader did not reject FakeTCP before mutation: %v", err)
	}
	if _, err := os.Lstat(forbiddenPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("baseline gate touched forbidden run-owned pin candidate: %s: %v", forbiddenPin, err)
	}
	after := snapshotFakeTCPRealHostKernel(t, prepared.contract)
	if !reflect.DeepEqual(after, active) {
		t.Fatalf("baseline gate changed experimental link identity: before=%#v after=%#v", active, after)
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("close FakeTCP mutual-exclusion runtime: %v", err)
	}
	closed = true
	assertFakeTCPRealHostKernelEmpty(t, prepared.contract)
	t.Logf("FAKETCP_REALHOST_MUTUAL_EXCLUSION_COMPLETE run_id=%s restored=1", prepared.contract.runID)
}

func requireFakeTCPRealHostPrepared(t *testing.T) fakeTCPRealHostPrepared {
	t.Helper()
	enabled, err := fakeTCPRealHostGateEnabled(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Skipf("set %s=1 only through the reviewed real-host controller", fakeTCPRealHostGateEnv)
	}
	if os.Geteuid() != 0 {
		t.Fatal("explicit FakeTCP real-host integration requires root")
	}
	contract, err := parseFakeTCPRealHostContract(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	validateFakeTCPRealHostTempRootIdentity(t, contract)
	experimentalSpec, experimentalIdentity, err := loadFakeTCPRealHostObject(contract.experimentalObject)
	if err != nil {
		t.Fatal(err)
	}
	if experimentalIdentity.Embedded || experimentalIdentity.Source != contract.experimentalObject {
		t.Fatalf("experimental object identity = %#v", experimentalIdentity)
	}
	if err := validateExperimentalExtensionManifest(experimentalSpec); err != nil {
		t.Fatalf("validate experimental object %s (%s): %v",
			experimentalIdentity.Source, experimentalIdentity.SHA256, err)
	}
	baselineSpec, baselineIdentity, err := loadFakeTCPRealHostObject(contract.baselineObject)
	if err != nil {
		t.Fatal(err)
	}
	if baselineIdentity.Embedded || baselineIdentity.Source != contract.baselineObject {
		t.Fatalf("baseline object identity = %#v", baselineIdentity)
	}
	if err := validateBaselineCollectionSpec(baselineSpec); err != nil {
		t.Fatalf("validate baseline object %s (%s): %v", baselineIdentity.Source, baselineIdentity.SHA256, err)
	}
	validateFakeTCPRealHostOwnedVethPair(t, contract)
	assertFakeTCPRealHostKernelEmpty(t, contract)
	return fakeTCPRealHostPrepared{
		contract: contract, experimentalSpec: experimentalSpec, baselineSpec: baselineSpec,
	}
}

func loadFakeTCPRealHostObject(path string) (*ebpf.CollectionSpec, ObjectIdentity, error) {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, ObjectIdentity{}, fmt.Errorf("resolve reviewed BPF object %s: %w", path, err)
	}
	if canonical != path {
		return nil, ObjectIdentity{}, fmt.Errorf("reviewed BPF object path %s resolves to %s", path, canonical)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ObjectIdentity{}, fmt.Errorf("open reviewed BPF object %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ObjectIdentity{}, fmt.Errorf("own reviewed BPF object descriptor %s", path)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		closeErr := file.Close()
		return nil, ObjectIdentity{}, errors.Join(
			fmt.Errorf("inspect reviewed BPF object %s: %w", path, err),
			closeErr,
		)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Nlink != 1 ||
		stat.Mode&0o022 != 0 || stat.Size <= 0 || stat.Size > fakeTCPRealHostObjectSizeLimit {
		closeErr := file.Close()
		return nil, ObjectIdentity{}, errors.Join(
			fmt.Errorf(
				"reviewed BPF object %s has unsafe identity mode=%#o uid=%d nlink=%d size=%d",
				path, stat.Mode, stat.Uid, stat.Nlink, stat.Size,
			),
			closeErr,
		)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, fakeTCPRealHostObjectSizeLimit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, ObjectIdentity{}, errors.Join(
			wrapNonNilError("read reviewed BPF object "+path, readErr),
			wrapNonNilError("close reviewed BPF object "+path, closeErr),
		)
	}
	if len(data) == 0 || len(data) > fakeTCPRealHostObjectSizeLimit {
		return nil, ObjectIdentity{}, fmt.Errorf("reviewed BPF object %s has invalid size %d", path, len(data))
	}
	identity := objectIdentity(path, false, data)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
	if err != nil {
		return nil, identity, fmt.Errorf("parse reviewed BPF object %s: %w", path, err)
	}
	return spec, identity, nil
}

func validateFakeTCPRealHostTempRootIdentity(t *testing.T, contract fakeTCPRealHostContract) {
	t.Helper()
	canonical, err := filepath.EvalSymlinks(contract.tempRoot)
	if err != nil {
		t.Fatalf("resolve reviewed FakeTCP real-host temp root: %v", err)
	}
	if canonical != contract.tempRoot {
		t.Fatalf("reviewed FakeTCP real-host temp root resolves to %s", canonical)
	}
	var stat unix.Stat_t
	if err := unix.Lstat(contract.tempRoot, &stat); err != nil {
		t.Fatalf("inspect reviewed FakeTCP real-host temp root: %v", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 || stat.Nlink < 2 || stat.Mode&0o077 != 0 {
		t.Fatalf("reviewed FakeTCP real-host temp root has unsafe identity mode=%#o uid=%d nlink=%d",
			stat.Mode, stat.Uid, stat.Nlink)
	}
}

func validateFakeTCPRealHostOwnedVethPair(t *testing.T, contract fakeTCPRealHostContract) {
	t.Helper()
	selfNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initialNetNS, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if selfNetNS != initialNetNS || !strings.HasPrefix(selfNetNS, "net:[") {
		t.Fatalf("FakeTCP real-host test is not in the initial network namespace: self=%s pid1=%s",
			selfNetNS, initialNetNS)
	}
	for _, endpoint := range []struct {
		ifindex     int
		name        string
		alias       string
		peerIfindex int
	}{
		{contract.ifindex, contract.vethName, contract.vethAlias, contract.peerIfindex},
		{contract.peerIfindex, contract.peerVethName, contract.peerVethAlias, contract.ifindex},
	} {
		link, err := netlink.LinkByIndex(endpoint.ifindex)
		if err != nil {
			t.Fatalf("resolve reviewed veth ifindex %d: %v", endpoint.ifindex, err)
		}
		attrs := link.Attrs()
		if attrs == nil || attrs.Index != endpoint.ifindex || attrs.Name != endpoint.name ||
			attrs.Alias != endpoint.alias || link.Type() != "veth" || attrs.Flags&net.FlagUp == 0 ||
			len(attrs.HardwareAddr) != 6 {
			t.Fatalf("reviewed veth identity mismatch: link=%T attrs=%#v want ifindex=%d name=%s alias=%s",
				link, attrs, endpoint.ifindex, endpoint.name, endpoint.alias)
		}
		iflinkPath := filepath.Join("/sys/class/net", endpoint.name, "iflink")
		iflinkBytes, err := os.ReadFile(iflinkPath)
		if err != nil {
			t.Fatalf("read reviewed veth peer identity %s: %v", iflinkPath, err)
		}
		iflink := strings.TrimSuffix(string(iflinkBytes), "\n")
		parsed, err := parseFakeTCPRealHostIfindex("veth iflink", iflink)
		if err != nil || parsed != endpoint.peerIfindex {
			t.Fatalf("reviewed veth %s iflink=%q error=%v, want %d",
				endpoint.name, iflink, err, endpoint.peerIfindex)
		}
	}
}

func buildFakeTCPRealHostRuntime(
	ctx context.Context,
	t *testing.T,
	prepared fakeTCPRealHostPrepared,
	withXOR bool,
	leaseSuffix string,
) (*ExperimentalFakeTCPRuntime, *fakeTCPRealHostSlowPath) {
	t.Helper()
	generationText := prepared.contract.runID
	generation, err := strconv.ParseUint(generationText, 16, 32)
	if err != nil || generation == 0 {
		t.Fatalf("derive FakeTCP real-host generation from %s: %v", generationText, err)
	}
	generation++
	state := fakeTCPRealHostState(prepared.contract, generation, withXOR)
	baselineSnapshot, err := abi.FromStateWithGeneration(state, generation)
	if err != nil {
		t.Fatal(err)
	}
	fakeSnapshot, err := buildFakeTCPPolicySnapshot(state, generation)
	if err != nil {
		t.Fatal(err)
	}

	leaseBase := "faketcp-" + prepared.contract.runID + "-" + leaseSuffix
	leasePath := filepath.Join(prepared.contract.tempRoot, leaseBase+".lease")
	maintenancePath := filepath.Join(prepared.contract.tempRoot, leaseBase+".maintenance")
	leaseCtx := lockfile.WithLifecyclePathsForTest(ctx, leasePath, maintenancePath)
	lease, err := lockfile.AcquireLifecycle(leaseCtx, lockfile.LifecycleOwner{
		PID: os.Getpid(), Action: "faketcp-realhost-" + leaseSuffix, RunDir: prepared.contract.tempRoot,
	})
	if err != nil {
		t.Fatalf("acquire run-owned FakeTCP lifecycle lease: %v", err)
	}
	isolation := &fakeTCPRealHostGenerationIsolation{
		generation: generation,
		ifindexes:  []int{prepared.contract.ifindex, prepared.contract.peerIfindex},
	}
	transaction, err := newFakeTCPPolicyGenerationTransaction(leaseCtx, generation, lease, isolation)
	if err != nil {
		closeErr := lease.Close()
		t.Fatalf("create FakeTCP real-host generation transaction: %v", errors.Join(err, closeErr))
	}
	if err := lease.Close(); err != nil {
		transactionErr := transaction.Close()
		t.Fatalf("release caller copy of FakeTCP lifecycle lease: %v", errors.Join(err, transactionErr))
	}

	dependencies := liveExperimentalCollectionAcquisitionDependencies()
	newOwner := dependencies.newOwner
	dependencies.newOwner = func(collection *ebpf.Collection) (*experimentalCollectionOwner, error) {
		owner, ownerErr := newOwner(collection)
		if owner != nil {
			ownerErr = errors.Join(ownerErr, isolation.bind(owner))
		}
		return owner, ownerErr
	}
	slowPath := newFakeTCPRealHostSlowPath()
	runtime, err := acquireAndBuildExperimentalFakeTCPRuntime(
		leaseCtx,
		prepared.experimentalSpec.Copy(),
		prepared.contract.experimentalObject,
		dependencies,
		experimentalFakeTCPRuntimeBuildOptions{
			transaction:      transaction,
			baselineSnapshot: baselineSnapshot,
			snapshot:         fakeSnapshot,
			attachState:      state,
			xdpRequests: []fakeTCPXDPAttachRequest{
				{IfIndex: prepared.contract.ifindex, Mode: fakeTCPXDPAttachGeneric},
				{IfIndex: prepared.contract.peerIfindex, Mode: fakeTCPXDPAttachGeneric},
			},
			xdpRuntime:    liveFakeTCPXDPRuntime,
			engineOptions: fakeTCPRealHostEngineOptions(generation),
			slowPathFactory: func(_ *faketcp.Engine, events *ebpf.Map) (experimentalSlowPath, error) {
				if events == nil {
					return nil, errors.New("FakeTCP real-host events map is nil")
				}
				info, err := events.Info()
				if err != nil {
					return nil, fmt.Errorf("inspect FakeTCP real-host events map: %w", err)
				}
				if info.Name != "faketcp_events" {
					return nil, fmt.Errorf("FakeTCP real-host events map name=%q", info.Name)
				}
				return slowPath, nil
			},
		},
	)
	if err != nil {
		if runtime != nil {
			err = errors.Join(err, runtime.Close())
		}
		t.Fatalf("build FakeTCP real-host runtime: %v", err)
	}
	if runtime == nil {
		t.Fatal("build FakeTCP real-host runtime returned nil")
	}
	return runtime, slowPath
}

func fakeTCPRealHostState(
	contract fakeTCPRealHostContract,
	generation uint64,
	withXOR bool,
) *control.State {
	const (
		profileID = uint32(1)
		cipherID  = uint32(1)
		wgID      = uint32(1)
	)
	state := &control.State{
		Generation: generation,
		Profiles: []control.ProfileState{{
			ID: profileID, Name: "realhost",
			StandardToMixed: [4]uint32{0xa1b2c3d4, 0xb2c3d4e5, 0xc3d4e5f6, 0x13dff06b},
			MixedToStandard: [4]uint32{1, 2, 3, 4},
		}},
		WireGuards: []control.WireGuardState{{
			ID: wgID, Name: "realhost", ProfileID: profileID,
			TransportMode: "faketcp", FakeTCPExperimental: true,
			FakeTCPChecksumMode: config.FakeTCPChecksumModePartialCompleteReset,
			FakeTCPIngressMode:  "xdp-required", FakeTCPSYNRateIntervalNanos: int64(20 * time.Millisecond),
			FakeTCPSYNBurst: 4,
		}},
		Underlays: []control.UnderlayState{
			{ID: 1, Name: contract.vethName, IfName: contract.vethName, LinkType: "veth", Parser: "ethernet", IfIndex: contract.ifindex, Role: "transform", Resolved: true},
			{ID: 2, Name: contract.peerVethName, IfName: contract.peerVethName, LinkType: "veth", Parser: "ethernet", IfIndex: contract.peerIfindex, Role: "transform", Resolved: true},
		},
	}
	selectedCipher := uint32(0)
	if withXOR {
		selectedCipher = cipherID
		var key [256]byte
		for index := range key {
			key[index] = byte(index*17 + 5)
		}
		state.Ciphers = []control.CipherState{{
			ID: cipherID, Name: "realhost-xor", Mode: "xor", Auth: "none",
			Scope: "wg-payload-full", KeyDerivation: "wgmx-hkdf256-v1",
			KeyLen: 256, KeyMask: 255, MaxBytes: 2048, Key: key,
		}}
		state.WireGuards[0].CipherID = cipherID
	}
	for _, endpoint := range []struct {
		ifindex         int
		sourcePort      uint16
		destinationPort uint16
	}{
		{contract.ifindex, 31001, 31001},
		{contract.peerIfindex, 31002, 31002},
	} {
		state.EgressRules = append(state.EgressRules, control.EgressRule{
			Generation: generation, Family: "ipv4", SourcePort: endpoint.sourcePort,
			UnderlayIfIndex: endpoint.ifindex, ProfileID: profileID, CipherID: selectedCipher,
			WGID: wgID, Action: "rewrite", TransportMode: "faketcp",
		})
		state.IngressListeners = append(state.IngressListeners, control.IngressListener{
			Generation: generation, Family: "ipv4", DestinationPort: endpoint.destinationPort,
			UnderlayIfIndex: endpoint.ifindex, ProfileID: profileID, CipherID: selectedCipher,
			WGID: wgID, Action: "rewrite", TransportMode: "faketcp",
		})
	}
	return state
}

func fakeTCPRealHostEngineOptions(generation uint64) faketcp.Options {
	return faketcp.Options{
		Generation: generation, SessionCapacity: 32,
		MaxHalfOpenSessions: 16, MaxHalfOpenPerSource: 4,
		SYNRateInterval: 20 * time.Millisecond, SYNBurst: 4, SYNBurstPerSource: 2,
		SYNSourceLedgerCapacity: 32, SYNSourceLedgerTTL: time.Second,
		MaxPendingFlows: 8, MaxPendingPacketsPerFlow: 4, MaxPendingBytes: 64 * 1024,
		HandshakeTimeout: time.Second, HandshakeRetries: 2,
		KeepaliveInterval: 5 * time.Second, IdleTimeout: 20 * time.Second,
		Window: 4096, Now: time.Now, MonotonicClock: faketcp.LinuxMonotonicClock{},
		InitialSequence: func() uint32 { return 0x01020304 },
	}
}

func snapshotFakeTCPRealHostKernel(
	t *testing.T,
	contract fakeTCPRealHostContract,
) fakeTCPRealHostKernelSnapshot {
	t.Helper()
	snapshot := fakeTCPRealHostKernelSnapshot{
		xdp: make(map[int]fakeTCPXDPProbe, 2),
		tcx: make(map[fakeTCPRealHostTCXSlot][]fakeTCPRealHostTCXProgram, 4),
	}
	for _, ifindex := range []int{contract.ifindex, contract.peerIfindex} {
		probe, err := probeLiveFakeTCPXDP(ifindex)
		if err != nil {
			t.Fatalf("probe FakeTCP real-host XDP ifindex %d: %v", ifindex, err)
		}
		snapshot.xdp[ifindex] = probe
		for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
			programs, err := queryFakeTCPRealHostTCX(ifindex, attach)
			if err != nil {
				t.Fatal(err)
			}
			snapshot.tcx[fakeTCPRealHostTCXSlot{ifindex: ifindex, attach: attach}] = programs
		}
	}
	return snapshot
}

func queryFakeTCPRealHostTCX(
	ifindex int,
	attach ebpf.AttachType,
) ([]fakeTCPRealHostTCXProgram, error) {
	result, err := ciliumlink.QueryPrograms(ciliumlink.QueryOptions{Target: ifindex, Attach: attach})
	if err != nil {
		return nil, fmt.Errorf("query FakeTCP real-host TCX %s ifindex %d: %w", attach, ifindex, err)
	}
	if result == nil || result.Revision == 0 {
		return nil, fmt.Errorf("query FakeTCP real-host TCX %s ifindex %d returned no revision fence", attach, ifindex)
	}
	programs := make([]fakeTCPRealHostTCXProgram, 0, len(result.Programs))
	for _, attached := range result.Programs {
		linkID, ok := attached.LinkID()
		if !ok || linkID == 0 || attached.ID == 0 {
			return nil, fmt.Errorf("query FakeTCP real-host TCX %s ifindex %d returned incomplete identity", attach, ifindex)
		}
		programs = append(programs, fakeTCPRealHostTCXProgram{
			programID: uint32(attached.ID), linkID: uint32(linkID),
		})
	}
	return programs, nil
}

func assertFakeTCPRealHostKernelEmpty(t *testing.T, contract fakeTCPRealHostContract) {
	t.Helper()
	snapshot := snapshotFakeTCPRealHostKernel(t, contract)
	for ifindex, probe := range snapshot.xdp {
		if probe.Attached || probe.ProgramID != 0 {
			t.Fatalf("run-owned veth ifindex %d already has XDP identity %#v", ifindex, probe)
		}
	}
	for slot, programs := range snapshot.tcx {
		if len(programs) != 0 {
			t.Fatalf("run-owned veth TCX slot %#v already has programs %#v", slot, programs)
		}
	}
}

func assertFakeTCPRealHostRuntimeAttached(
	t *testing.T,
	contract fakeTCPRealHostContract,
) fakeTCPRealHostKernelSnapshot {
	t.Helper()
	snapshot := snapshotFakeTCPRealHostKernel(t, contract)
	for ifindex, probe := range snapshot.xdp {
		if !probe.Attached || probe.ProgramID == 0 {
			t.Fatalf("FakeTCP runtime has no exact XDP identity on ifindex %d: %#v", ifindex, probe)
		}
	}
	for slot, programs := range snapshot.tcx {
		if len(programs) != 1 || programs[0].programID == 0 || programs[0].linkID == 0 {
			t.Fatalf("FakeTCP runtime TCX slot %#v identities=%#v, want exactly one", slot, programs)
		}
	}
	return snapshot
}

func installFakeTCPRealHostSessions(
	t *testing.T,
	handles ExperimentalFakeTCPRuntimeHandles,
	generation uint64,
	contract fakeTCPRealHostContract,
) {
	t.Helper()
	localA, err := faketcp.RawIPv4BE32(netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	localB, err := faketcp.RawIPv4BE32(netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	for _, session := range []struct {
		key   abi.FakeTCPSessionKey
		value abi.FakeTCPSessionValue
	}{
		{
			key: abi.FakeTCPSessionKey{
				Generation: generation, LocalIPv4: localA, RemoteIPv4: localB,
				UnderlayIndex: uint32(contract.ifindex), LocalPort: 31001, RemotePort: 31002,
			},
			value: abi.FakeTCPSessionValue{
				Generation: generation, TXSequence: 0x01020304, RXSequence: 0x11223344,
				Window: 4096, State: abi.FakeTCPStateEstablished,
			},
		},
		{
			key: abi.FakeTCPSessionKey{
				Generation: generation, LocalIPv4: localB, RemoteIPv4: localA,
				UnderlayIndex: uint32(contract.peerIfindex), LocalPort: 31002, RemotePort: 31001,
			},
			value: abi.FakeTCPSessionValue{
				Generation: generation, TXSequence: 0x11223344, RXSequence: 0x01020304,
				Window: 4096, State: abi.FakeTCPStateEstablished,
			},
		},
	} {
		if err := handles.SessionStore().InsertEstablished(session.key, session.value); err != nil {
			t.Fatalf("insert FakeTCP real-host established session %#v: %v", session.key, err)
		}
	}
}

func readFakeTCPRealHostStat(t *testing.T, runtime *ExperimentalFakeTCPRuntime, key uint32) uint64 {
	t.Helper()
	return readFakeTCPRealHostStats(t, runtime, "faketcp_stats_map", 13)[key]
}

func readFakeTCPRealHostCoreStat(t *testing.T, runtime *ExperimentalFakeTCPRuntime, key uint32) uint64 {
	t.Helper()
	return readFakeTCPRealHostStats(t, runtime, "stats_map", 36)[key]
}

func readFakeTCPRealHostStats(
	t *testing.T,
	runtime *ExperimentalFakeTCPRuntime,
	mapName string,
	count int,
) []uint64 {
	t.Helper()
	if runtime == nil || runtime.state == nil || runtime.state.collection == nil {
		t.Fatal("FakeTCP real-host runtime collection is unavailable")
	}
	if count <= 0 {
		t.Fatalf("invalid FakeTCP real-host stat count %d", count)
	}
	stats, err := runtime.state.collection.mapResource(mapName)
	if err != nil {
		t.Fatal(err)
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	totals := make([]uint64, count)
	for index := range count {
		key := uint32(index)
		values := make([]uint64, possibleCPUs)
		if err := stats.Lookup(&key, &values); err != nil {
			t.Fatalf("read FakeTCP real-host map %s stat %d: %v", mapName, key, err)
		}
		for _, value := range values {
			totals[index] += value
		}
	}
	return totals
}

func waitForFakeTCPRealHostStat(
	t *testing.T,
	runtime *ExperimentalFakeTCPRuntime,
	mapName string,
	key uint32,
	want uint64,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		values := readFakeTCPRealHostStats(t, runtime, mapName, int(key)+1)
		if values[key] == want {
			return
		}
		if values[key] > want || time.Now().After(deadline) {
			t.Fatalf("FakeTCP real-host map %s stat %d=%d, want %d", mapName, key, values[key], want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openFakeTCPRealHostPacketSocket(t *testing.T, ifindex int) int {
	t.Helper()
	protocol := fakeTCPRealHostHTONS(unix.ETH_P_ALL)
	fd, err := unix.Socket(
		unix.AF_PACKET,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		int(protocol),
	)
	if err != nil {
		t.Fatalf("open run-owned veth packet socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: ifindex}); err != nil {
		closeErr := unix.Close(fd)
		t.Fatalf("bind run-owned veth packet socket: %v", errors.Join(err, closeErr))
	}
	return fd
}

func closeFakeTCPRealHostFD(t *testing.T, fd int, label string) {
	t.Helper()
	if fd >= 0 {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close %s: %v", label, err)
		}
	}
}

func receiveFakeTCPRealHostUDPPacket(
	ctx context.Context,
	fd int,
	sourcePort uint16,
	destinationPort uint16,
) ([]byte, error) {
	buffer := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("receive FakeTCP real-host packet: context has no deadline")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		timeout := int(remaining / time.Millisecond)
		if timeout < 1 {
			timeout = 1
		}
		if timeout > 1000 {
			timeout = 1000
		}
		pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		count, err := unix.Poll(pollFDs, timeout)
		if errors.Is(err, unix.EINTR) || count == 0 {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("poll FakeTCP real-host packet socket: %w", err)
		}
		if pollFDs[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return nil, fmt.Errorf("poll FakeTCP real-host packet socket returned events %#x", pollFDs[0].Revents)
		}
		length, _, err := unix.Recvfrom(fd, buffer, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("receive FakeTCP real-host packet: %w", err)
		}
		frame := buffer[:length]
		if fakeTCPRealHostUDPFrameMatches(frame, sourcePort, destinationPort) {
			return append([]byte(nil), frame...), nil
		}
	}
}

func fakeTCPRealHostUDPFrameMatches(frame []byte, sourcePort, destinationPort uint16) bool {
	if len(frame) < 14+20+8 || frame[12] != 0x08 || frame[13] != 0x00 {
		return false
	}
	ip := frame[14:]
	if ip[0] != 0x45 || ip[9] != 17 || !bytes.Equal(ip[12:16], []byte{10, 0, 0, 1}) ||
		!bytes.Equal(ip[16:20], []byte{10, 0, 0, 2}) {
		return false
	}
	udp := ip[20:]
	return uint16(udp[0])<<8|uint16(udp[1]) == sourcePort &&
		uint16(udp[2])<<8|uint16(udp[3]) == destinationPort
}

func fakeTCPRealHostHTONS(value uint16) uint16 {
	return value<<8 | value>>8
}
