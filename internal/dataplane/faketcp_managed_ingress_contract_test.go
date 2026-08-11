package dataplane

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func TestFakeTCPManagedIngressRotationTypewordFixture(t *testing.T) {
	const (
		rotationBytes = 12
		mixedType     = uint32(0x13dff06b)
		invalidPrefix = uint32(0xfeedface)
	)
	payload := make([]byte, 32)
	for index := range payload {
		payload[index] = byte(index*29 + 7)
	}
	binary.LittleEndian.PutUint32(payload[:4], mixedType)
	binary.LittleEndian.PutUint32(payload[rotationBytes:rotationBytes+4], invalidPrefix)
	wire := append(append([]byte(nil), payload[rotationBytes:]...), payload[:rotationBytes]...)
	if got := binary.LittleEndian.Uint32(wire[:4]); got != invalidPrefix {
		t.Fatalf("rotated wire prefix=%#x, want deliberately invalid %#x", got, invalidPrefix)
	}
	if got := binary.LittleEndian.Uint32(wire[len(wire)-rotationBytes:]); got != mixedType {
		t.Fatalf("rotated wire tail typeword=%#x, want %#x", got, mixedType)
	}
	restored := append(append([]byte(nil), wire[len(wire)-rotationBytes:]...), wire[:len(wire)-rotationBytes]...)
	if !bytes.Equal(restored, payload) {
		t.Fatalf("inverse rotation=%x, want=%x", restored, payload)
	}
}

func TestFakeTCPManagedIngressEarlyDropSourceOrderAndABI(t *testing.T) {
	sourceBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	action := sourceSection(
		t, source,
		"static __always_inline int faketcp_xdp_l3_action(",
		"static __always_inline int faketcp_xdp_reject(",
	)
	for _, want := range []string{
		"parse_rc == FAKETCP_L3_SAFE_BYPASS || !managed_interface",
		"FAKETCP_L3_TRUNCATED",
		"FAKETCP_L3_MALFORMED",
		"FAKETCP_STAT_BAD_PACKET",
		"FAKETCP_STAT_ADMISSION_BYPASS_REJECT",
	} {
		if !strings.Contains(action, want) {
			t.Fatalf("single managed-ingress action mapper is missing %q", want)
		}
	}
	if strings.Count(action, "inc_faketcp_stat(") != 1 ||
		strings.Index(action, "!managed_interface") > strings.Index(action, "inc_faketcp_stat(") {
		t.Fatal("SAFE_BYPASS/unmanaged traffic can reach or duplicate early-drop accounting")
	}
	checkpoint := sourceSection(
		t, source,
		"static __always_inline int faketcp_xdp_admission_checkpoint(",
		"static __always_inline int faketcp_xdp_l3_action(",
	)
	if !strings.Contains(checkpoint, "ip_off + admission->wire_total_len -") ||
		strings.Contains(checkpoint, "ip_off + sizeof(*iph) + sizeof(*tcp)") {
		t.Fatal("XDP admission does not bind only the tail-restored typeword")
	}
	consumer := sourceSection(
		t, source,
		"static __always_inline int faketcp_consume_ingress_admission(",
		"static __always_inline int faketcp_xdp_managed_interface(",
	)
	if !strings.Contains(consumer,
		"bpf_skb_load_bytes(skb, info->payload_off, &input_wire",
	) {
		t.Fatal("TC ingress no longer binds metadata to the inverse-rotated payload typeword")
	}
	bodyMarker := "faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)"
	bodyStart := strings.Index(source, bodyMarker)
	wrapperStart := strings.Index(source, "SEC(\"xdp\")\nint wg_mix_faketcp_ingress(struct xdp_md *xdp)")
	if bodyStart < 0 || wrapperStart < 0 || bodyStart >= wrapperStart {
		t.Fatal("managed-ingress accounting is not wholly inside the generation-guarded XDP body")
	}
	xdp := sourceSection(
		t, source, bodyMarker,
		"admission_decision = faketcp_xdp_admission_checkpoint(",
	)
	ordered := []string{
		"managed_interface = faketcp_xdp_managed_interface",
		"parse_rc = faketcp_xdp_l3_start",
		"parse_action = faketcp_xdp_l3_action",
		"parse_rc = faketcp_parse_l3",
		"wire_ports = data + l3->l4_off",
		"managed_listener = faketcp_xdp_managed_port",
		"faketcp_managed_transform_status(l3, l3->transport_protocol)",
		"l3->transport_protocol == IPPROTO_UDP",
		"policy_listener = lookup_ingress_listener",
	}
	position := -1
	for _, marker := range ordered {
		next := strings.Index(xdp, marker)
		if next <= position {
			t.Fatalf("managed-ingress source order is missing or inverted at %q", marker)
		}
		position = next
	}
	if strings.Count(xdp, "parse_action = faketcp_xdp_l3_action") != 2 {
		t.Fatal("managed-ingress XDP path does not use exactly two parser action mappings")
	}
	if strings.Count(xdp, "return XDP_DROP;") != 1 ||
		!strings.Contains(xdp, "if (!scratch)\n\t\treturn XDP_DROP;") {
		t.Fatal("early managed-ingress path has a direct drop outside the per-CPU scratch fail-closed gate")
	}
	if fakeTCPImplementedCapabilities&fakeTCPCapabilityManagedIngressParser != 0 {
		t.Fatal("managed-ingress capability opened before .82 live evidence")
	}
	manifestBytes, err := os.ReadFile("experimental_manifest_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(manifestBytes),
		`{name: "faketcp_stats_map", mapType: ebpf.PerCPUArray, keySize: 4, valueSize: 8, maxEntries: 19}`,
	) != 1 {
		t.Fatal("managed-ingress acceptance changed the fixed 19-entry FakeTCP stats ABI")
	}
}
