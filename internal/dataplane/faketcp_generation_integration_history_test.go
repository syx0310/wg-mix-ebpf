package dataplane

import (
	"bytes"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

const (
	generationIntegrationMerge     = "a814841419fb62cb74596cdbfab5626399b063d4"
	generationIntegrationTopic     = "5818657997d58c1d21f14f4a36c75f80684fed59"
	generationIntegrationCanonical = "7decdf4ad1dade39c93135d8f43f77c24e1204ce"
	generationIntegrationBase      = "d28585bfaaefe44c0e71d2cbbced494da96dd7fa"
	generationIntegrationConflict  = "bpf/wg_mix_faketcp.h"
)

func TestFakeTCPGenerationManagedIngressIntegrationHistory(t *testing.T) {
	parents := strings.Fields(string(runGenerationIntegrationGit(
		t, "show", "-s", "--format=%P", generationIntegrationMerge,
	)))
	wantParents := []string{generationIntegrationTopic, generationIntegrationCanonical}
	if len(parents) != len(wantParents) || parents[0] != wantParents[0] || parents[1] != wantParents[1] {
		t.Fatalf("integration parents=%q, want=%q", parents, wantParents)
	}
	if base := strings.TrimSpace(string(runGenerationIntegrationGit(
		t, "merge-base", generationIntegrationTopic, generationIntegrationCanonical,
	))); base != generationIntegrationBase {
		t.Fatalf("integration merge-base=%q, want=%q", base, generationIntegrationBase)
	}

	base := generationIntegrationTree(t, generationIntegrationBase)
	topic := generationIntegrationTree(t, generationIntegrationTopic)
	canonical := generationIntegrationTree(t, generationIntegrationCanonical)
	merged := generationIntegrationTree(t, generationIntegrationMerge)
	paths := make(map[string]struct{}, len(base)+len(topic)+len(canonical)+len(merged))
	for _, tree := range []map[string]string{base, topic, canonical, merged} {
		for path := range tree {
			paths[path] = struct{}{}
		}
	}
	conflicts := make([]string, 0, 1)
	for path := range paths {
		baseEntry, topicEntry, canonicalEntry := base[path], topic[path], canonical[path]
		var want string
		switch {
		case topicEntry == canonicalEntry:
			want = topicEntry
		case topicEntry == baseEntry:
			want = canonicalEntry
		case canonicalEntry == baseEntry:
			want = topicEntry
		default:
			conflicts = append(conflicts, path)
			continue
		}
		if merged[path] != want {
			t.Fatalf("non-conflict path %q merge entry=%q, want source entry=%q", path, merged[path], want)
		}
	}
	sort.Strings(conflicts)
	if len(conflicts) != 1 || conflicts[0] != generationIntegrationConflict {
		t.Fatalf("integration conflict paths=%q, want only %q", conflicts, generationIntegrationConflict)
	}
	combined := strings.Fields(string(runGenerationIntegrationGit(
		t, "diff-tree", "--cc", "--name-only", "--format=", "-r", generationIntegrationMerge,
	)))
	if len(combined) != 1 || combined[0] != generationIntegrationConflict {
		t.Fatalf("combined resolution paths=%q, want only %q", combined, generationIntegrationConflict)
	}
}

func TestFakeTCPGenerationManagedIngressIntegrationShape(t *testing.T) {
	sourceBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	for marker, want := range map[string]int{
		"SEC(\"xdp\")": 1,
		"int wg_mix_faketcp_ingress(struct xdp_md *xdp)":                            1,
		"faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)":            1,
		"bpf_map_lookup_elem(&faketcp_managed_if_map":                               1,
		"bpf_map_lookup_elem(&faketcp_managed_port_map":                             1,
		"bpf_map_lookup_elem(&faketcp_control_policy_map":                           1,
		"ip_off + admission->wire_total_len -\n\t\t\t\t       FAKETCP_HEADER_DELTA": 1,
	} {
		if got := strings.Count(source, marker); got != want {
			t.Fatalf("integration marker %q count=%d, want=%d", marker, got, want)
		}
	}
	body := sourceSection(t, source,
		"faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)",
		"SEC(\"xdp\")")
	wrapper := sourceSection(t, source,
		"int wg_mix_faketcp_ingress(struct xdp_md *xdp)", "#endif")
	assertGenerationWrapper(t, wrapper,
		"faketcp_generation_enter(generation)",
		"faketcp_xdp_ingress_body(xdp, generation)",
		"faketcp_generation_exit(generation)")
	activeAt := strings.Index(wrapper, "active_generation(&generation)")
	enterAt := strings.Index(wrapper, "faketcp_generation_enter(generation)")
	if activeAt < 0 || activeAt >= enterAt {
		t.Fatal("XDP wrapper does not select the active generation before acquiring its token")
	}
	if strings.Count(body, "parse_action = faketcp_xdp_l3_action") != 2 ||
		strings.Count(body, "admission_decision = faketcp_xdp_admission_checkpoint(") != 1 {
		t.Fatal("managed early accounting/typeword admission escaped the guarded XDP body")
	}
}

func generationIntegrationTree(t *testing.T, commit string) map[string]string {
	t.Helper()
	raw := runGenerationIntegrationGit(t, "ls-tree", "-r", "-z", "--full-tree", commit)
	tree := make(map[string]string)
	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		entry, path, ok := bytes.Cut(record, []byte{'\t'})
		if !ok || len(path) == 0 {
			t.Fatalf("malformed ls-tree record for %s: %q", commit, record)
		}
		tree[string(path)] = string(entry)
	}
	return tree
}

func runGenerationIntegrationGit(t *testing.T, args ...string) []byte {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", "../.."}, args...)...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %q failed: %v\n%s", args, err, output)
	}
	return bytes.TrimSpace(output)
}
