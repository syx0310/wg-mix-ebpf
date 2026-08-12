//go:build linux

package dataplane

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/syx0310/wg-mix-ebpf/internal/config"
	"golang.org/x/sys/unix"
)

const (
	fakeTCPKprobeBridgeABIVersion     = uint32(1)
	fakeTCPKprobeStatusStructSize     = uint32(64)
	fakeTCPKprobeGetStatusIOCTL       = uintptr(0x80405701) // _IOR('W', 0x01, status_v1[64])
	fakeTCPKprobeCapChecksumState     = uint64(1 << 0)
	fakeTCPKprobeCapPartialReset      = uint64(1 << 1)
	fakeTCPKprobeCapPMTU              = uint64(1 << 2)
	fakeTCPKprobeCapUDPGSOToTCP       = uint64(1 << 3)
	fakeTCPKprobeCapFailClosed        = uint64(1 << 4)
	fakeTCPKprobeCapMultiLease        = uint64(1 << 5)
	fakeTCPKprobeStatusLeaseActive    = uint32(1 << 0)
	fakeTCPKprobeStatusProbesReady    = uint32(1 << 1)
	fakeTCPKprobeStatusHealthy        = uint32(1 << 2)
	fakeTCPKprobeRequiredCapabilities = fakeTCPKprobeCapChecksumState | fakeTCPKprobeCapPartialReset | fakeTCPKprobeCapPMTU | fakeTCPKprobeCapUDPGSOToTCP | fakeTCPKprobeCapFailClosed | fakeTCPKprobeCapMultiLease
	fakeTCPKprobeRequiredStatusFlags  = fakeTCPKprobeStatusLeaseActive | fakeTCPKprobeStatusProbesReady | fakeTCPKprobeStatusHealthy
)

var fakeTCPKprobeTriggerSymbols = []string{
	"bpf_skb_change_proto",
	"bpf_skb_change_type",
}

type fakeTCPKprobeLease struct {
	file *os.File
}

func (lease *fakeTCPKprobeLease) Close() error {
	if lease == nil || lease.file == nil {
		return nil
	}
	err := lease.file.Close()
	if err == nil {
		lease.file = nil
	}
	return err
}

// fakeTCPKprobeStatusV1 mirrors
// wg_mix_faketcp_checksum_kprobe_status_v1 byte-for-byte. Keep the explicit
// layout tests in sync with the kernel UAPI before changing this type.
type fakeTCPKprobeStatusV1 struct {
	ABIVersion   uint32
	StructSize   uint32
	Capabilities uint64
	Cookie       uint64
	PrepareHits  uint64
	CommitHits   uint64
	Errors       uint64
	NMissed      uint64
	Flags        uint32
	Reserved     uint32
}

type fakeTCPKprobeRuntimeProbe struct {
	module       string
	leasePath    string
	status       fakeTCPKprobeStatusV1
	capabilities []string
	lease        io.Closer
	ioctlStatus  func(*os.File, *fakeTCPKprobeStatusV1) error
	requirements []FakeTCPChecksumRequirement
}

type fakeTCPKprobeProbeDependencies struct {
	moduleRoot    string
	leasePath     string
	openLease     func(string) (*os.File, error)
	stat          func(string) (os.FileInfo, error)
	kernelConfig  func() (map[string]string, string, error)
	kernelSymbols func() (map[string]bool, error)
	ioctlStatus   func(*os.File, *fakeTCPKprobeStatusV1) error
}

func resolveFakeTCPChecksumBackend(
	ctx context.Context,
	requested string,
) (*FakeTCPChecksumSelection, error) {
	return resolveFakeTCPChecksumBackendWith(
		ctx,
		requested,
		fakeTCPChecksumBackendDependencies{
			probeKfunc: probeFakeTCPKfuncForChecksumSelection,
			acquireKprobe: func(ctx context.Context) (fakeTCPKprobeBackendAcquisition, error) {
				probe, err := acquireFakeTCPKprobeRuntime(ctx, liveFakeTCPKprobeProbeDependencies())
				if err != nil {
					return fakeTCPKprobeBackendAcquisition{}, err
				}
				return fakeTCPKprobeBackendAcquisition{
					module:       probe.module,
					capabilities: probe.capabilities,
					cookie:       probe.status.Cookie,
					lease:        probe.lease,
					health: func(healthCtx context.Context, cookie uint64) error {
						return probe.healthy(healthCtx, cookie)
					},
				}, nil
			},
		},
	)
}

func probeFakeTCPChecksumBackends(ctx context.Context) []FakeTCPChecksumBackendProbe {
	kfunc := FakeTCPChecksumBackendProbe{
		Backend:      config.FakeTCPChecksumBackendKfunc,
		Capability:   FakeTCPChecksumCapabilityFullGSOV1,
		Capabilities: append([]string(nil), fullFakeTCPChecksumCapabilities...),
		Module:       DefaultFakeTCPKfuncModule,
	}
	if err := ProbeFakeTCPKernelDependency(); err != nil {
		kfunc.Error = err.Error()
		kfunc.Unsupported = isFakeTCPKfuncExplicitlyUnsupported(err)
		kfunc.Requirements = []FakeTCPChecksumRequirement{{
			Name: "module-btf-and-kfunc-prototypes", Status: "FAIL", Message: err.Error(),
		}}
	} else {
		kfunc.Available = true
		kfunc.Equivalent = true
		kfunc.Requirements = []FakeTCPChecksumRequirement{{
			Name: "module-btf-and-kfunc-prototypes", Status: "PASS",
			Detail: "exact prepare and GSO commit kfunc prototypes",
		}}
	}

	kprobe := FakeTCPChecksumBackendProbe{
		Backend:   config.FakeTCPChecksumBackendKprobe,
		Module:    DefaultFakeTCPKprobeModule,
		LeasePath: DefaultFakeTCPKprobeLeaseDevice,
	}
	probe, err := acquireFakeTCPKprobeRuntime(ctx, liveFakeTCPKprobeProbeDependencies())
	if probe != nil {
		kprobe.Requirements = probe.requirements
		kprobe.Capabilities = append([]string(nil), probe.capabilities...)
		if capabilityErr := validateEquivalentFakeTCPChecksumCapabilities(probe.capabilities); capabilityErr == nil {
			kprobe.Equivalent = true
			kprobe.Capability = FakeTCPChecksumCapabilityFullGSOV1
		}
		if probe.lease != nil {
			if closeErr := probe.lease.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close temporary kprobe module lease: %w", closeErr))
			}
		}
	}
	if err != nil {
		kprobe.Error = err.Error()
	} else if kprobe.Equivalent {
		kprobe.Available = true
	} else {
		kprobe.Error = "kprobe bridge does not advertise full-GSO equivalent capabilities"
	}
	return []FakeTCPChecksumBackendProbe{kfunc, kprobe}
}

func probeFakeTCPKfuncForChecksumSelection() error {
	err := ProbeFakeTCPKernelDependency()
	if err == nil {
		return nil
	}
	if isFakeTCPKfuncExplicitlyUnsupported(err) {
		return errors.Join(ErrFakeTCPChecksumBackendUnsupported, err)
	}
	return err
}

func isFakeTCPKfuncExplicitlyUnsupported(err error) bool {
	return errors.Is(err, btf.ErrNotFound) ||
		errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOTSUP)
}

func liveFakeTCPKprobeProbeDependencies() fakeTCPKprobeProbeDependencies {
	return fakeTCPKprobeProbeDependencies{
		moduleRoot: "/sys/module/" + DefaultFakeTCPKprobeModule,
		leasePath:  DefaultFakeTCPKprobeLeaseDevice,
		openLease: func(path string) (*os.File, error) {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return nil, err
			}
			return os.NewFile(uintptr(fd), path), nil
		},
		stat:          os.Stat,
		kernelConfig:  readRunningKernelConfig,
		kernelSymbols: readRunningKernelSymbols,
		ioctlStatus:   ioctlFakeTCPKprobeStatus,
	}
}

func acquireFakeTCPKprobeRuntime(
	ctx context.Context,
	dependencies fakeTCPKprobeProbeDependencies,
) (*fakeTCPKprobeRuntimeProbe, error) {
	if ctx == nil {
		return nil, errors.New("probe FakeTCP kprobe bridge: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dependencies.openLease == nil || dependencies.stat == nil ||
		dependencies.kernelConfig == nil || dependencies.kernelSymbols == nil ||
		dependencies.ioctlStatus == nil {
		return nil, errors.New("probe FakeTCP kprobe bridge: dependencies are incomplete")
	}
	probe := &fakeTCPKprobeRuntimeProbe{
		module:    filepath.Base(dependencies.moduleRoot),
		leasePath: dependencies.leasePath,
	}
	var requirementErrs []error
	if _, err := dependencies.stat(dependencies.moduleRoot); err != nil {
		probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
			Name: "module", Status: "FAIL", Detail: probe.module, Message: err.Error(),
		})
		requirementErrs = append(requirementErrs, fmt.Errorf("required kprobe module %q is unavailable: %w", probe.module, err))
	} else {
		probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
			Name: "module", Status: "PASS", Detail: probe.module,
		})
	}

	if kernelConfig, source, err := dependencies.kernelConfig(); err != nil {
		for _, name := range []string{"CONFIG_KPROBES", "CONFIG_KRETPROBES", "CONFIG_KALLSYMS"} {
			probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
				Name: name, Status: "WARN", Detail: source, Message: err.Error(),
			})
		}
	} else {
		for _, name := range []string{"CONFIG_KPROBES", "CONFIG_KRETPROBES", "CONFIG_KALLSYMS"} {
			value := kernelConfig[name]
			status := "PASS"
			message := ""
			if value != "y" && value != "m" {
				status = "FAIL"
				message = "kernel option is not enabled"
			}
			probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
				Name: name, Status: status, Detail: source + ":" + value, Message: message,
			})
			if status == "FAIL" {
				requirementErrs = append(requirementErrs, fmt.Errorf("%s is not enabled in %s", name, source))
			}
		}
	}

	if symbols, err := dependencies.kernelSymbols(); err != nil {
		for _, symbol := range fakeTCPKprobeTriggerSymbols {
			probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
				Name: "symbol." + symbol, Status: "WARN", Message: err.Error(),
			})
		}
	} else {
		for _, symbol := range fakeTCPKprobeTriggerSymbols {
			status := "PASS"
			message := ""
			if !symbols[symbol] {
				status = "FAIL"
				message = "symbol is absent from /proc/kallsyms"
			}
			probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
				Name: "symbol." + symbol, Status: status, Message: message,
			})
			if status == "FAIL" {
				requirementErrs = append(requirementErrs, fmt.Errorf("required kprobe trigger symbol %q is unavailable", symbol))
			}
		}
	}

	file, err := dependencies.openLease(dependencies.leasePath)
	if err != nil {
		probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
			Name: "module-lease", Status: "FAIL", Detail: dependencies.leasePath, Message: err.Error(),
		})
		requirementErrs = append(requirementErrs, fmt.Errorf("open kprobe module lease %s: %w", dependencies.leasePath, err))
		return probe, errors.Join(requirementErrs...)
	}
	lease := &fakeTCPKprobeLease{file: file}
	probe.lease = lease
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
			Name: "module-lease", Status: "FAIL", Detail: dependencies.leasePath, Message: err.Error(),
		})
		return probe, errors.Join(fmt.Errorf("stat kprobe module lease: %w", err), lease.Close())
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
			Name: "module-lease", Status: "FAIL", Detail: dependencies.leasePath,
			Message: "opened path is not a character device",
		})
		return probe, errors.Join(fmt.Errorf("kprobe module lease %s is not a character device", dependencies.leasePath), lease.Close())
	}
	probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
		Name: "module-lease", Status: "PASS", Detail: dependencies.leasePath,
	})
	if len(requirementErrs) != 0 {
		return probe, errors.Join(errors.Join(requirementErrs...), lease.Close())
	}

	var status fakeTCPKprobeStatusV1
	if err := dependencies.ioctlStatus(file, &status); err != nil {
		probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
			Name: "bridge-status-ioctl", Status: "FAIL", Message: err.Error(),
		})
		return probe, errors.Join(fmt.Errorf("query kprobe module lease status: %w", err), lease.Close())
	}
	probe.requirements = append(probe.requirements, FakeTCPChecksumRequirement{
		Name: "bridge-status-ioctl", Status: "PASS", Detail: "GET_STATUS v1",
	})
	probe.status = status
	probe.ioctlStatus = dependencies.ioctlStatus
	capabilities, requirements, statusErr := validateFakeTCPKprobeStatus(status, 0)
	probe.capabilities = capabilities
	probe.requirements = append(probe.requirements, requirements...)
	if statusErr != nil {
		return probe, errors.Join(statusErr, lease.Close())
	}
	return probe, nil
}

func (probe *fakeTCPKprobeRuntimeProbe) healthy(ctx context.Context, cookie uint64) error {
	if probe == nil || probe.lease == nil {
		return errors.New("FakeTCP kprobe bridge lease is unavailable")
	}
	if ctx == nil {
		return errors.New("FakeTCP kprobe health context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lease, ok := probe.lease.(*fakeTCPKprobeLease)
	if !ok || lease.file == nil {
		return errors.New("FakeTCP kprobe bridge lease has no live device file")
	}
	if cookie == 0 {
		return errors.New("FakeTCP kprobe bridge runtime cookie is unavailable")
	}
	if probe.ioctlStatus == nil {
		return errors.New("FakeTCP kprobe bridge has no status ioctl")
	}
	var status fakeTCPKprobeStatusV1
	if err := probe.ioctlStatus(lease.file, &status); err != nil {
		return fmt.Errorf("query FakeTCP kprobe bridge health: %w", err)
	}
	if _, _, err := validateFakeTCPKprobeStatus(status, cookie); err != nil {
		return fmt.Errorf("validate FakeTCP kprobe bridge health: %w", err)
	}
	return ctx.Err()
}

func ioctlFakeTCPKprobeStatus(file *os.File, status *fakeTCPKprobeStatusV1) error {
	if file == nil || status == nil {
		return errors.New("kprobe status ioctl received a nil file or status buffer")
	}
	if unsafe.Sizeof(*status) != uintptr(fakeTCPKprobeStatusStructSize) {
		return fmt.Errorf(
			"kprobe status Go layout is %d bytes, want %d",
			unsafe.Sizeof(*status), fakeTCPKprobeStatusStructSize,
		)
	}
	*status = fakeTCPKprobeStatusV1{}
	for {
		_, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			file.Fd(),
			fakeTCPKprobeGetStatusIOCTL,
			uintptr(unsafe.Pointer(status)),
		)
		runtime.KeepAlive(file)
		runtime.KeepAlive(status)
		if errno == 0 {
			return nil
		}
		if errno != unix.EINTR {
			return errno
		}
	}
}

func validateFakeTCPKprobeStatus(
	status fakeTCPKprobeStatusV1,
	expectedCookie uint64,
) ([]string, []FakeTCPChecksumRequirement, error) {
	capabilities := fakeTCPKprobeCapabilityNames(status.Capabilities)
	requirements := make([]FakeTCPChecksumRequirement, 0, 10)
	var failures []error
	check := func(name, detail string, err error) {
		requirement := FakeTCPChecksumRequirement{Name: name, Status: "PASS", Detail: detail}
		if err != nil {
			requirement.Status = "FAIL"
			requirement.Message = err.Error()
			failures = append(failures, err)
		}
		requirements = append(requirements, requirement)
	}

	var err error
	if status.ABIVersion != fakeTCPKprobeBridgeABIVersion {
		err = fmt.Errorf("kprobe bridge ABI=%d, want %d", status.ABIVersion, fakeTCPKprobeBridgeABIVersion)
	}
	check("bridge-abi", fmt.Sprintf("%d", status.ABIVersion), err)
	err = nil
	if status.StructSize != fakeTCPKprobeStatusStructSize {
		err = fmt.Errorf("kprobe bridge status size=%d, want %d", status.StructSize, fakeTCPKprobeStatusStructSize)
	}
	check("bridge-struct-size", fmt.Sprintf("%d", status.StructSize), err)
	err = nil
	if status.Reserved != 0 {
		err = errors.New("kprobe bridge status reserved field is nonzero")
	}
	check("bridge-reserved", "zero", err)

	missingCapabilities := fakeTCPKprobeCapabilityNames(
		fakeTCPKprobeRequiredCapabilities &^ status.Capabilities,
	)
	err = nil
	if len(missingCapabilities) != 0 {
		err = fmt.Errorf("kprobe bridge is missing capabilities %s", strings.Join(missingCapabilities, ","))
	}
	check("bridge-capabilities", strings.Join(capabilities, ","), err)

	for _, flag := range []struct {
		name string
		mask uint32
	}{
		{name: "lease-active", mask: fakeTCPKprobeStatusLeaseActive},
		{name: "probes-ready", mask: fakeTCPKprobeStatusProbesReady},
		{name: "bridge-healthy", mask: fakeTCPKprobeStatusHealthy},
	} {
		err = nil
		if status.Flags&flag.mask == 0 {
			err = fmt.Errorf("kprobe bridge status flag %s is not set", flag.name)
		}
		check(flag.name, "set", err)
	}

	err = nil
	if status.NMissed != 0 {
		err = fmt.Errorf("kprobe bridge has %d missed return probes", status.NMissed)
	}
	check("kretprobe-nmissed", fmt.Sprintf("%d", status.NMissed), err)
	err = nil
	if status.Errors != 0 {
		err = fmt.Errorf("kprobe bridge reports %d internal errors", status.Errors)
	}
	check("bridge-errors", fmt.Sprintf("%d", status.Errors), err)
	err = nil
	if status.Cookie == 0 {
		err = errors.New("kprobe bridge returned a zero runtime cookie")
	} else if expectedCookie != 0 && status.Cookie != expectedCookie {
		err = errors.New("kprobe bridge lease identity changed")
	}
	check("runtime-cookie", "issued and redacted", err)

	return capabilities, requirements, errors.Join(failures...)
}

func fakeTCPKprobeCapabilityNames(capabilities uint64) []string {
	known := []struct {
		mask uint64
		name string
	}{
		{fakeTCPKprobeCapChecksumState, "checksum-state"},
		{fakeTCPKprobeCapPartialReset, "partial-reset"},
		{fakeTCPKprobeCapPMTU, "pmtu"},
		{fakeTCPKprobeCapUDPGSOToTCP, "udp-gso-to-tcp"},
		{fakeTCPKprobeCapFailClosed, "fail-closed"},
		{fakeTCPKprobeCapMultiLease, "multi-lease"},
	}
	names := make([]string, 0, len(known))
	for _, capability := range known {
		if capabilities&capability.mask != 0 {
			names = append(names, capability.name)
		}
	}
	return names
}

func readRunningKernelConfig() (map[string]string, string, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return nil, "", fmt.Errorf("uname: %w", err)
	}
	releaseBytes := make([]byte, 0, len(uts.Release))
	for _, value := range uts.Release {
		if value == 0 {
			break
		}
		releaseBytes = append(releaseBytes, byte(value))
	}
	release := string(releaseBytes)
	paths := []string{"/proc/config.gz", filepath.Join("/boot", "config-"+release)}
	var failures []error
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", path, err))
			continue
		}
		var reader io.Reader = file
		var gz *gzip.Reader
		if strings.HasSuffix(path, ".gz") {
			gz, err = gzip.NewReader(file)
			if err != nil {
				_ = file.Close()
				failures = append(failures, fmt.Errorf("%s: %w", path, err))
				continue
			}
			reader = gz
		}
		values, parseErr := parseKernelConfig(reader)
		if gz != nil {
			parseErr = errors.Join(parseErr, gz.Close())
		}
		parseErr = errors.Join(parseErr, file.Close())
		if parseErr != nil {
			failures = append(failures, fmt.Errorf("%s: %w", path, parseErr))
			continue
		}
		return values, path, nil
	}
	return nil, strings.Join(paths, ","), errors.Join(failures...)
}

func parseKernelConfig(reader io.Reader) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "CONFIG_") {
			name, value, ok := strings.Cut(line, "=")
			if ok {
				values[name] = value
			}
			continue
		}
		if strings.HasPrefix(line, "# CONFIG_") && strings.HasSuffix(line, " is not set") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "# "), " is not set")
			values[name] = "n"
		}
	}
	return values, scanner.Err()
}

func readRunningKernelSymbols() (map[string]bool, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	wanted := make(map[string]struct{}, len(fakeTCPKprobeTriggerSymbols))
	for _, symbol := range fakeTCPKprobeTriggerSymbols {
		wanted[symbol] = struct{}{}
	}
	found := make(map[string]bool, len(wanted))
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		name := strings.TrimSuffix(fields[2], " ["+DefaultFakeTCPKprobeModule+"]")
		if _, ok := wanted[name]; ok {
			found[name] = true
		}
	}
	return found, scanner.Err()
}

func (l LinuxLoader) effectiveFakeTCPObjectPathForChecksumBackend(
	backend string,
) (path string, variant string, err error) {
	switch backend {
	case config.FakeTCPChecksumBackendKfunc:
		return l.effectiveFakeTCPObjectPath(), FakeTCPObjectVariantModernKfunc, nil
	case config.FakeTCPChecksumBackendKprobe:
		return l.effectiveFakeTCPLegacy515ObjectPath(), FakeTCPObjectVariantLegacy515, nil
	default:
		return "", "", fmt.Errorf("checksum backend %q is not resolved", backend)
	}
}

// loadValidatedFakeTCPCollectionSpecForChecksumBackend is the single object
// family switch for production planning. It binds each resolved checksum
// backend to its independent object identity and exact manifest. Callers must
// invoke it only after ResolveFakeTCPChecksumBackend succeeds and before any
// baseline detach or other dataplane mutation.
func (l LinuxLoader) loadValidatedFakeTCPCollectionSpecForChecksumBackend(
	backend string,
) (*ebpf.CollectionSpec, ObjectIdentity, string, error) {
	path, variant, err := l.effectiveFakeTCPObjectPathForChecksumBackend(backend)
	if err != nil {
		return nil, ObjectIdentity{}, "", err
	}
	var spec *ebpf.CollectionSpec
	var identity ObjectIdentity
	switch backend {
	case config.FakeTCPChecksumBackendKfunc:
		spec, identity, err = loadFakeTCPCollectionSpecFromResolvedPath(path)
		if err == nil {
			err = validateExperimentalExtensionManifest(spec)
		}
	case config.FakeTCPChecksumBackendKprobe:
		spec, identity, err = loadFakeTCPLegacy515CollectionSpecFromResolvedPath(path)
		if err == nil {
			err = validateLegacy515ExtensionManifest(spec)
		}
	default:
		return nil, ObjectIdentity{}, "", fmt.Errorf("checksum backend %q is not resolved", backend)
	}
	if err != nil {
		return nil, identity, variant, fmt.Errorf(
			"load %s FakeTCP object for %s checksum backend: %w",
			variant, backend, err,
		)
	}
	return spec, identity, variant, nil
}
