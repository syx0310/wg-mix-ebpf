package dataplane

import (
	"os"
	"strings"
	"testing"
)

func TestFakeTCPRealHostGateIsExplicitAndFailClosed(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   string
		present bool
		want    bool
		wantErr bool
	}{
		{name: "unset"},
		{name: "empty", present: true},
		{name: "enabled", value: "1", present: true, want: true},
		{name: "false-ish", value: "0", present: true, wantErr: true},
		{name: "whitespace", value: " 1", present: true, wantErr: true},
		{name: "other", value: "yes", present: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			enabled, err := fakeTCPRealHostGateEnabled(func(name string) (string, bool) {
				if name != fakeTCPRealHostGateEnv || !test.present {
					return "", false
				}
				return test.value, true
			})
			if (err != nil) != test.wantErr || enabled != test.want {
				t.Fatalf("enabled=%t error=%v, want enabled=%t error=%t", enabled, err, test.want, test.wantErr)
			}
		})
	}
	if _, err := fakeTCPRealHostGateEnabled(nil); err == nil {
		t.Fatal("nil environment lookup was accepted")
	}
}

func TestParseFakeTCPRealHostContract(t *testing.T) {
	values := validFakeTCPRealHostEnvironment()
	contract, err := parseFakeTCPRealHostContract(mapFakeTCPRealHostEnvironment(values))
	if err != nil {
		t.Fatal(err)
	}
	if contract.experimentalObject != "/run/wg-mix-ebpf-source-stages/c8e41d73/source/build/wg_mix_faketcp_experimental.o" ||
		contract.baselineObject != "/run/wg-mix-ebpf-source-stages/c8e41d73/source/build/wg_mix_tc.o" ||
		contract.ifindex != 101 || contract.peerIfindex != 102 ||
		contract.xdpMode != fakeTCPRealHostXDPGeneric || contract.runID != "c8e41d73" ||
		contract.tempRoot != "/run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp-realhost" ||
		contract.vethName != "wgc8e41a" || contract.peerVethName != "wgc8e41b" ||
		contract.vethAlias != "wg-mix-ebpf:c8e41d73:a" ||
		contract.peerVethAlias != "wg-mix-ebpf:c8e41d73:b" {
		t.Fatalf("parsed contract = %#v", contract)
	}
	if _, err := parseFakeTCPRealHostContract(nil); err == nil {
		t.Fatal("nil environment lookup was accepted")
	}
}

func TestParseFakeTCPRealHostContractRejectsDriftBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
		match  string
	}{
		{
			name: "missing object",
			mutate: func(values map[string]string) {
				delete(values, fakeTCPRealHostObjectEnv)
			},
			match: "is required",
		},
		{
			name: "relative object",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostObjectEnv] = "build/wg_mix_faketcp_experimental.o"
			},
			match: "clean absolute path",
		},
		{
			name: "unclean object",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostObjectEnv] = "/run/wg-mix-ebpf-source-stages/c8e41d73/source/build/../build/wg_mix_faketcp_experimental.o"
			},
			match: "clean absolute path",
		},
		{
			name: "wrong experimental basename",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostObjectEnv] = "/run/wg-mix-ebpf-source-stages/c8e41d73/source/build/not-reviewed.o"
			},
			match: "basename",
		},
		{
			name: "different build root",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostBaselineObjectEnv] = "/other/source/build/wg_mix_tc.o"
			},
			match: "reviewed v6 build directory",
		},
		{
			name: "foreign shared build root",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostObjectEnv] = "/other/source/build/wg_mix_faketcp_experimental.o"
				values[fakeTCPRealHostBaselineObjectEnv] = "/other/source/build/wg_mix_tc.o"
			},
			match: "reviewed v6 build directory",
		},
		{
			name: "different run object root",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostObjectEnv] = "/run/wg-mix-ebpf-source-stages/aaaaaaaa/source/build/wg_mix_faketcp_experimental.o"
				values[fakeTCPRealHostBaselineObjectEnv] = "/run/wg-mix-ebpf-source-stages/aaaaaaaa/source/build/wg_mix_tc.o"
			},
			match: "reviewed v6 build directory",
		},
		{
			name: "zero ifindex",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostIfindexEnv] = "0"
			},
			match: "canonical positive decimal",
		},
		{
			name: "noncanonical ifindex",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostIfindexEnv] = "0101"
			},
			match: "canonical positive decimal",
		},
		{
			name: "ifindex overflow",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostIfindexEnv] = "4294967296"
			},
			match: "canonical positive decimal",
		},
		{
			name: "same endpoints",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostPeerIfindexEnv] = values[fakeTCPRealHostIfindexEnv]
			},
			match: "distinct veth endpoints",
		},
		{
			name: "native mode",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostXDPModeEnv] = "native"
			},
			match: "exactly generic",
		},
		{
			name: "uppercase run ID",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostRunIDEnv] = "C8E41D73"
			},
			match: "lower-case nonzero hexadecimal",
		},
		{
			name: "path-shaped run ID",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostRunIDEnv] = "../e41d7"
			},
			match: "lower-case nonzero hexadecimal",
		},
		{
			name: "zero run ID",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostRunIDEnv] = "00000000"
			},
			match: "lower-case nonzero hexadecimal",
		},
		{
			name: "foreign temp root",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostTempRootEnv] = "/tmp"
			},
			match: "reviewed v6 temporary directory",
		},
		{
			name: "different run temp root",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostTempRootEnv] = "/run/wg-mix-ebpf-source-stages/aaaaaaaa/go-tmp-realhost"
			},
			match: "reviewed v6 temporary directory",
		},
		{
			name: "newline injection",
			mutate: func(values map[string]string) {
				values[fakeTCPRealHostIfindexEnv] = "101\n102"
			},
			match: "whitespace or control characters",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := validFakeTCPRealHostEnvironment()
			test.mutate(values)
			contract, err := parseFakeTCPRealHostContract(mapFakeTCPRealHostEnvironment(values))
			if err == nil || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("contract=%#v error=%v, want error containing %q", contract, err, test.match)
			}
		})
	}
}

func TestFakeTCPRealHostLinuxEntryPointStaticContract(t *testing.T) {
	contents, err := os.ReadFile("faketcp_realhost_linux_test.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(contents)
	for _, required := range []string{
		"func TestExperimentalFakeTCPRealHostLifecycleIntegration(t *testing.T)",
		"func TestFakeTCPRealHostXORTypewordHeaderCompositionIntegration(t *testing.T)",
		"func TestBaselineExperimentalRealHostMutualExclusionIntegration(t *testing.T)",
		"fakeTCPRealHostGateEnabled(os.LookupEnv)",
		"validateFakeTCPRealHostOwnedVethPair(t, contract)",
		"assertFakeTCPRealHostKernelEmpty(t, contract)",
		"fakeTCPRealHostStatCount",
		"fakeTCPRealHostStatChecksumNoneAccepted",
		"fakeTCPRealHostStatChecksumPartialReset",
		"unix.PACKET_VNET_HDR",
		"unix.VIRTIO_NET_HDR_F_NEEDS_CSUM",
		"unix.VIRTIO_NET_HDR_GSO_UDP_L4",
		"sendFakeTCPRealHostGSOProbe",
		"assertNoFakeTCPRealHostGSOProbePacket",
		"TestFakeTCPRealHostGSOProbeIsolationContract",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FakeTCP real-host Linux test source is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"os.Remove(",
		"os.RemoveAll(",
		"exec.Command(",
		"find -delete",
		"rm -rf",
		"/sys/fs/bpf",
		"t.Parallel()",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("FakeTCP real-host Linux test source contains forbidden operation %q", forbidden)
		}
	}
}

func validFakeTCPRealHostEnvironment() map[string]string {
	return map[string]string{
		fakeTCPRealHostObjectEnv:         "/run/wg-mix-ebpf-source-stages/c8e41d73/source/build/wg_mix_faketcp_experimental.o",
		fakeTCPRealHostBaselineObjectEnv: "/run/wg-mix-ebpf-source-stages/c8e41d73/source/build/wg_mix_tc.o",
		fakeTCPRealHostIfindexEnv:        "101",
		fakeTCPRealHostPeerIfindexEnv:    "102",
		fakeTCPRealHostXDPModeEnv:        "generic",
		fakeTCPRealHostRunIDEnv:          "c8e41d73",
		fakeTCPRealHostTempRootEnv:       "/run/wg-mix-ebpf-source-stages/c8e41d73/go-tmp-realhost",
	}
}

func mapFakeTCPRealHostEnvironment(values map[string]string) fakeTCPRealHostEnvLookup {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}
