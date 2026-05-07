package feature

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type Probe struct {
	GOOS                    string            `json:"goos"`
	GOARCH                  string            `json:"goarch"`
	SupportedArch           bool              `json:"supported_arch"`
	ProcAvailable           bool              `json:"proc_available"`
	SysFSAvailable          bool              `json:"sysfs_available"`
	BPFFSAvailable          bool              `json:"bpffs_available"`
	BPFFSMounted            bool              `json:"bpffs_mounted"`
	BPFJITStatus            string            `json:"bpf_jit_status,omitempty"`
	UnprivilegedBPFDisabled string            `json:"unprivileged_bpf_disabled,omitempty"`
	KernelModules           map[string]bool   `json:"kernel_modules"`
	Commands                map[string]string `json:"commands"`
	Warnings                []string          `json:"warnings,omitempty"`
}

func Run() Probe {
	p := Probe{
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		SupportedArch: supportedArch(runtime.GOARCH),
		KernelModules: make(map[string]bool),
		Commands:      make(map[string]string),
	}
	p.ProcAvailable = exists("/proc")
	p.SysFSAvailable = exists("/sys/fs")
	p.BPFFSAvailable = exists("/sys/fs/bpf")
	p.BPFFSMounted = mountedAs("/sys/fs/bpf", "bpf")
	if data, err := os.ReadFile("/proc/sys/net/core/bpf_jit_enable"); err == nil {
		p.BPFJITStatus = string(bytesTrimSpace(data))
	}
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		p.UnprivilegedBPFDisabled = string(bytesTrimSpace(data))
	}
	for _, module := range []string{"sched_cls", "cls_bpf", "sch_ingress", "act_bpf"} {
		p.KernelModules[module] = exists("/sys/module/" + module)
	}
	for _, name := range []string{"tc", "nft", "wg"} {
		if path, err := exec.LookPath(name); err == nil {
			p.Commands[name] = path
		} else {
			p.Commands[name] = ""
			p.Warnings = append(p.Warnings, name+" not found in PATH")
		}
	}
	if runtime.GOOS != "linux" {
		p.Warnings = append(p.Warnings, "Linux is required for runtime dataplane operations")
	}
	if !p.SupportedArch {
		p.Warnings = append(p.Warnings, "architecture is outside MVP support matrix")
	}
	if p.SysFSAvailable && !p.BPFFSAvailable {
		p.Warnings = append(p.Warnings, "bpffs path /sys/fs/bpf is not available")
	}
	if p.BPFFSAvailable && !p.BPFFSMounted {
		p.Warnings = append(p.Warnings, "bpffs is not mounted on /sys/fs/bpf")
	}
	return p
}

func (p Probe) JSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

func supportedArch(arch string) bool {
	switch arch {
	case "amd64", "arm64":
		return true
	default:
		return false
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func mountedAs(path string, fsType string) bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == path && fields[2] == fsType {
			return true
		}
	}
	return false
}

func bytesTrimSpace(in []byte) []byte {
	for len(in) > 0 {
		switch in[0] {
		case ' ', '\n', '\r', '\t':
			in = in[1:]
		default:
			goto trimRight
		}
	}
trimRight:
	for len(in) > 0 {
		switch in[len(in)-1] {
		case ' ', '\n', '\r', '\t':
			in = in[:len(in)-1]
		default:
			return in
		}
	}
	return in
}
