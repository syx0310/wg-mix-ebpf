package feature

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
)

type Probe struct {
	GOOS           string            `json:"goos"`
	GOARCH         string            `json:"goarch"`
	SupportedArch  bool              `json:"supported_arch"`
	ProcAvailable  bool              `json:"proc_available"`
	SysFSAvailable bool              `json:"sysfs_available"`
	BPFJITStatus   string            `json:"bpf_jit_status,omitempty"`
	Commands       map[string]string `json:"commands"`
	Warnings       []string          `json:"warnings,omitempty"`
}

func Run() Probe {
	p := Probe{
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		SupportedArch: supportedArch(runtime.GOARCH),
		Commands:      make(map[string]string),
	}
	p.ProcAvailable = exists("/proc")
	p.SysFSAvailable = exists("/sys/fs")
	if data, err := os.ReadFile("/proc/sys/net/core/bpf_jit_enable"); err == nil {
		p.BPFJITStatus = string(bytesTrimSpace(data))
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
