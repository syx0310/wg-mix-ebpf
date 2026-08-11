package dataplane

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/syx0310/wg-mix-ebpf/internal/abi"
)

func TestFakeTCPGenerationBarrierStateABIIsOnePackedWord(t *testing.T) {
	flags := []uint64{
		abi.FakeTCPGenerationStateOpen,
		abi.FakeTCPGenerationStateSealed,
		abi.FakeTCPGenerationStatePoison,
		abi.FakeTCPGenerationStateWakeArmed,
	}
	var union uint64
	for i, flag := range flags {
		if flag == 0 || flag&(flag-1) != 0 || flag&abi.FakeTCPGenerationInflightMask != 0 {
			t.Fatalf("generation flag %d is not one reserved state bit: %#x", i, flag)
		}
		if union&flag != 0 {
			t.Fatalf("generation flag %d overlaps an earlier flag: %#x", i, flag)
		}
		union |= flag
	}
	if union != ^abi.FakeTCPGenerationInflightMask {
		t.Fatalf("state flags=%#x inflight mask=%#x do not partition one uint64", union, abi.FakeTCPGenerationInflightMask)
	}
}

const generationGateModelCASAttempts = 8

type generationGateModel struct {
	generation atomic.Uint64
	state      atomic.Uint64

	runtimeGeneration  uint64
	runtimeIncarnation [16]byte
	wakeAttempts       atomic.Uint32
	wakeEvents         atomic.Uint32
}

func newGenerationGateModel(generation uint64, incarnation [16]byte) *generationGateModel {
	return &generationGateModel{
		runtimeGeneration:  generation,
		runtimeIncarnation: incarnation,
	}
}

func (gate *generationGateModel) setRuntimeIdentity(generation uint64, incarnation [16]byte) {
	gate.runtimeGeneration = generation
	gate.runtimeIncarnation = incarnation
}

func (gate *generationGateModel) poison() uint32 {
	gate.state.Or(abi.FakeTCPGenerationStatePoison)
	return abi.FakeTCPGenerationResultPoison
}

func (gate *generationGateModel) bind(generation uint64) bool {
	bound := gate.generation.Load()
	if bound == 0 {
		gate.generation.CompareAndSwap(0, generation)
		bound = gate.generation.Load()
	}
	if bound != generation {
		gate.poison()
		return false
	}
	return true
}

func (gate *generationGateModel) control(
	operation uint32,
	generation uint64,
	incarnation [16]byte,
) uint32 {
	if generation == 0 || generation != gate.runtimeGeneration ||
		incarnation != gate.runtimeIncarnation || incarnation == ([16]byte{}) {
		return abi.FakeTCPGenerationResultMalformed
	}
	switch operation {
	case abi.FakeTCPGenerationControlAssertClosed:
		bound := gate.generation.Load()
		state := gate.state.Load()
		count := state & abi.FakeTCPGenerationInflightMask
		flags := state &^ abi.FakeTCPGenerationInflightMask
		if flags&abi.FakeTCPGenerationStatePoison != 0 {
			return abi.FakeTCPGenerationResultPoison
		}
		if bound != 0 && bound != generation {
			return gate.poison()
		}
		if state == 0 {
			return abi.FakeTCPGenerationResultIdle
		}
		if flags == abi.FakeTCPGenerationStateOpen ||
			(flags == abi.FakeTCPGenerationStateSealed && count == 0) ||
			flags == abi.FakeTCPGenerationStateSealed|abi.FakeTCPGenerationStateWakeArmed {
			return abi.FakeTCPGenerationResultMismatch
		}
		return gate.poison()
	case abi.FakeTCPGenerationControlOpen:
		return gate.open(generation)
	case abi.FakeTCPGenerationControlClose:
		return gate.close(generation)
	default:
		return abi.FakeTCPGenerationResultMalformed
	}
}

func (gate *generationGateModel) open(generation uint64) uint32 {
	if !gate.bind(generation) {
		return abi.FakeTCPGenerationResultPoison
	}
	for range generationGateModelCASAttempts {
		old := gate.state.Load()
		count := old & abi.FakeTCPGenerationInflightMask
		flags := old &^ abi.FakeTCPGenerationInflightMask
		switch {
		case flags&abi.FakeTCPGenerationStatePoison != 0:
			return abi.FakeTCPGenerationResultPoison
		case flags == abi.FakeTCPGenerationStateOpen:
			return abi.FakeTCPGenerationResultOpen
		case flags == abi.FakeTCPGenerationStateSealed && count == 0,
			flags == abi.FakeTCPGenerationStateSealed|abi.FakeTCPGenerationStateWakeArmed:
			return abi.FakeTCPGenerationResultMismatch
		case old != 0:
			return gate.poison()
		case gate.state.CompareAndSwap(0, abi.FakeTCPGenerationStateOpen):
			return abi.FakeTCPGenerationResultOpen
		}
	}
	return abi.FakeTCPGenerationResultMismatch
}

func (gate *generationGateModel) close(generation uint64) uint32 {
	if !gate.bind(generation) {
		return abi.FakeTCPGenerationResultPoison
	}
	for range generationGateModelCASAttempts {
		old := gate.state.Load()
		count := old & abi.FakeTCPGenerationInflightMask
		flags := old &^ abi.FakeTCPGenerationInflightMask
		if flags&abi.FakeTCPGenerationStatePoison != 0 {
			return abi.FakeTCPGenerationResultPoison
		}
		if old == 0 {
			if gate.state.CompareAndSwap(0, abi.FakeTCPGenerationStateSealed) {
				return abi.FakeTCPGenerationResultIdle
			}
			continue
		}
		if flags == abi.FakeTCPGenerationStateOpen {
			next := abi.FakeTCPGenerationStateSealed | count
			if count != 0 {
				next |= abi.FakeTCPGenerationStateWakeArmed
			}
			if !gate.state.CompareAndSwap(old, next) {
				continue
			}
			if count == 0 {
				return abi.FakeTCPGenerationResultIdle
			}
			return abi.FakeTCPGenerationResultWait
		}
		if flags == abi.FakeTCPGenerationStateSealed && count == 0 {
			return abi.FakeTCPGenerationResultIdle
		}
		if flags == abi.FakeTCPGenerationStateSealed|abi.FakeTCPGenerationStateWakeArmed {
			if count != 0 {
				return abi.FakeTCPGenerationResultWait
			}
			if gate.state.CompareAndSwap(old, abi.FakeTCPGenerationStateSealed) {
				return abi.FakeTCPGenerationResultIdle
			}
			continue
		}
		return gate.poison()
	}
	return abi.FakeTCPGenerationResultMismatch
}

func (gate *generationGateModel) enter(generation uint64) bool {
	return gate.enterCAS(generation, gate.state.CompareAndSwap)
}

func (gate *generationGateModel) enterCAS(
	generation uint64,
	compareAndSwap func(uint64, uint64) bool,
) bool {
	if generation == 0 {
		return false
	}
	bound := gate.generation.Load()
	if bound != generation {
		if bound != 0 || gate.state.Load() != 0 {
			gate.poison()
		}
		return false
	}
	for range generationGateModelCASAttempts {
		old := gate.state.Load()
		count := old & abi.FakeTCPGenerationInflightMask
		flags := old &^ abi.FakeTCPGenerationInflightMask
		if flags&abi.FakeTCPGenerationStatePoison != 0 {
			return false
		}
		if (flags == 0 && count == 0) ||
			(flags == abi.FakeTCPGenerationStateSealed && count == 0) ||
			flags == abi.FakeTCPGenerationStateSealed|abi.FakeTCPGenerationStateWakeArmed {
			return false
		}
		if flags != abi.FakeTCPGenerationStateOpen {
			gate.poison()
			return false
		}
		if count == abi.FakeTCPGenerationInflightMask {
			gate.poison()
			return false
		}
		if compareAndSwap(old, old+1) {
			return true
		}
	}
	return false
}

func (gate *generationGateModel) exit(generation uint64, ringOutputSucceeds bool) bool {
	old := gate.state.Add(^uint64(0)) + 1
	count := old & abi.FakeTCPGenerationInflightMask
	flags := old &^ abi.FakeTCPGenerationInflightMask
	if count == 0 || gate.generation.Load() != generation {
		gate.poison()
		return false
	}
	if flags&abi.FakeTCPGenerationStatePoison != 0 {
		return false
	}
	if flags != abi.FakeTCPGenerationStateOpen &&
		flags != abi.FakeTCPGenerationStateSealed|abi.FakeTCPGenerationStateWakeArmed {
		gate.poison()
		return false
	}
	if count != 1 || flags != abi.FakeTCPGenerationStateSealed|abi.FakeTCPGenerationStateWakeArmed {
		return false
	}
	if gate.runtimeGeneration != generation || gate.runtimeIncarnation == ([16]byte{}) {
		gate.poison()
		return false
	}
	gate.wakeAttempts.Add(1)
	if !ringOutputSucceeds {
		return false
	}
	gate.wakeEvents.Add(1)
	gate.state.CompareAndSwap(
		abi.FakeTCPGenerationStateSealed|abi.FakeTCPGenerationStateWakeArmed,
		abi.FakeTCPGenerationStateSealed,
	)
	return true
}

func openGenerationGateModel(t *testing.T) (*generationGateModel, [16]byte) {
	t.Helper()
	incarnation := [16]byte{1}
	gate := newGenerationGateModel(91, incarnation)
	if result := gate.control(abi.FakeTCPGenerationControlOpen, 91, incarnation); result != abi.FakeTCPGenerationResultOpen {
		t.Fatalf("model OPEN result=%d", result)
	}
	return gate, incarnation
}

func TestGenerationGateModelLinearizesEntryAndClose(t *testing.T) {
	t.Run("enter before close", func(t *testing.T) {
		gate, incarnation := openGenerationGateModel(t)
		if !gate.enter(91) {
			t.Fatal("OPEN generation rejected entry")
		}
		if result := gate.control(abi.FakeTCPGenerationControlClose, 91, incarnation); result != abi.FakeTCPGenerationResultWait {
			t.Fatalf("CLOSE result=%d, want WAIT", result)
		}
		if !gate.exit(91, true) || gate.state.Load() != abi.FakeTCPGenerationStateSealed {
			t.Fatalf("last exit did not converge sealed idle: state=%#x", gate.state.Load())
		}
	})

	t.Run("close before entry CAS", func(t *testing.T) {
		gate, incarnation := openGenerationGateModel(t)
		closeResult := uint32(0)
		first := true
		entered := gate.enterCAS(91, func(old, next uint64) bool {
			if first {
				first = false
				closeResult = gate.control(abi.FakeTCPGenerationControlClose, 91, incarnation)
			}
			return gate.state.CompareAndSwap(old, next)
		})
		if entered || closeResult != abi.FakeTCPGenerationResultIdle ||
			gate.state.Load() != abi.FakeTCPGenerationStateSealed {
			t.Fatalf("entry crossed close: entered=%t close=%d state=%#x",
				entered, closeResult, gate.state.Load())
		}
	})

	t.Run("CAS exhaustion does not count", func(t *testing.T) {
		gate, _ := openGenerationGateModel(t)
		attempts := 0
		if gate.enterCAS(91, func(uint64, uint64) bool {
			attempts++
			return false
		}) {
			t.Fatal("exhausted entry acquired a token")
		}
		if attempts != generationGateModelCASAttempts ||
			gate.state.Load() != abi.FakeTCPGenerationStateOpen {
			t.Fatalf("exhausted entry attempts=%d state=%#x", attempts, gate.state.Load())
		}
	})
}

func TestGenerationGateModelTerminalAndFailureTransitions(t *testing.T) {
	t.Run("close before open is terminal", func(t *testing.T) {
		incarnation := [16]byte{1}
		gate := newGenerationGateModel(91, incarnation)
		if result := gate.control(abi.FakeTCPGenerationControlClose, 91, incarnation); result != abi.FakeTCPGenerationResultIdle {
			t.Fatalf("terminal CLOSE result=%d", result)
		}
		if gate.generation.Load() != 91 || gate.state.Load() != abi.FakeTCPGenerationStateSealed {
			t.Fatalf("terminal CLOSE gate generation=%d state=%#x", gate.generation.Load(), gate.state.Load())
		}
		if result := gate.control(abi.FakeTCPGenerationControlOpen, 91, incarnation); result != abi.FakeTCPGenerationResultMismatch {
			t.Fatalf("OPEN after terminal CLOSE result=%d", result)
		}
	})

	t.Run("wake failure converges only on close retry", func(t *testing.T) {
		gate, incarnation := openGenerationGateModel(t)
		if !gate.enter(91) || gate.control(abi.FakeTCPGenerationControlClose, 91, incarnation) != abi.FakeTCPGenerationResultWait {
			t.Fatal("failed to arm one-waiter close")
		}
		if gate.exit(91, false) {
			t.Fatal("failed ring output reported a wake")
		}
		want := abi.FakeTCPGenerationStateSealed | abi.FakeTCPGenerationStateWakeArmed
		if gate.state.Load() != want || gate.wakeAttempts.Load() != 1 || gate.wakeEvents.Load() != 0 {
			t.Fatalf("failed wake state=%#x attempts=%d events=%d",
				gate.state.Load(), gate.wakeAttempts.Load(), gate.wakeEvents.Load())
		}
		if result := gate.control(abi.FakeTCPGenerationControlClose, 91, incarnation); result != abi.FakeTCPGenerationResultIdle ||
			gate.state.Load() != abi.FakeTCPGenerationStateSealed {
			t.Fatalf("retry CLOSE result=%d state=%#x", result, gate.state.Load())
		}
	})

	t.Run("wrong identity and generation fail closed", func(t *testing.T) {
		incarnation := [16]byte{1}
		gate := newGenerationGateModel(91, incarnation)
		wrongIncarnation := [16]byte{2}
		if result := gate.control(abi.FakeTCPGenerationControlAssertClosed, 91, wrongIncarnation); result != abi.FakeTCPGenerationResultMalformed ||
			gate.state.Load() != 0 || gate.generation.Load() != 0 {
			t.Fatalf("wrong incarnation result=%d generation=%d state=%#x",
				result, gate.generation.Load(), gate.state.Load())
		}
		if gate.control(abi.FakeTCPGenerationControlClose, 91, incarnation) != abi.FakeTCPGenerationResultIdle {
			t.Fatal("failed to terminally bind first identity")
		}
		gate.setRuntimeIdentity(92, wrongIncarnation)
		if result := gate.control(abi.FakeTCPGenerationControlOpen, 92, wrongIncarnation); result != abi.FakeTCPGenerationResultPoison ||
			gate.state.Load()&abi.FakeTCPGenerationStatePoison == 0 {
			t.Fatalf("wrong generation result=%d state=%#x", result, gate.state.Load())
		}
	})

	t.Run("overflow and underflow stick poison", func(t *testing.T) {
		overflow, _ := openGenerationGateModel(t)
		overflow.state.Store(abi.FakeTCPGenerationStateOpen | abi.FakeTCPGenerationInflightMask)
		if overflow.enter(91) || overflow.state.Load()&abi.FakeTCPGenerationStatePoison == 0 {
			t.Fatalf("overflow state=%#x", overflow.state.Load())
		}
		underflow, _ := openGenerationGateModel(t)
		if underflow.exit(91, true) || underflow.state.Load()&abi.FakeTCPGenerationStatePoison == 0 {
			t.Fatalf("underflow state=%#x", underflow.state.Load())
		}
	})

	t.Run("nested tokens produce one last-exit wake", func(t *testing.T) {
		gate, incarnation := openGenerationGateModel(t)
		if !gate.enter(91) || !gate.enter(91) ||
			gate.control(abi.FakeTCPGenerationControlClose, 91, incarnation) != abi.FakeTCPGenerationResultWait {
			t.Fatal("failed to arm nested-token close")
		}
		if gate.exit(91, true) || gate.wakeAttempts.Load() != 0 {
			t.Fatal("non-last nested exit emitted a wake")
		}
		if !gate.exit(91, true) || gate.wakeAttempts.Load() != 1 || gate.wakeEvents.Load() != 1 ||
			gate.state.Load() != abi.FakeTCPGenerationStateSealed {
			t.Fatalf("last nested exit attempts=%d events=%d state=%#x",
				gate.wakeAttempts.Load(), gate.wakeEvents.Load(), gate.state.Load())
		}
	})
}

func TestFakeTCPGenerationBarrierBPFContract(t *testing.T) {
	sourceBytes, err := os.ReadFile("../../bpf/wg_mix_faketcp.h")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	for _, name := range []string{"faketcp_gen_gt", "faketcp_gen_wk"} {
		if len(name) > 15 {
			t.Fatalf("kernel map name %q exceeds BPF's 15-byte name limit", name)
		}
	}
	for _, want := range []string{
		"__uint(type, BPF_MAP_TYPE_ARRAY);\n\t__uint(map_flags, BPF_F_RDONLY);\n\t__uint(max_entries, 1);",
		"} faketcp_gen_gt SEC(\".maps\");",
		"__uint(type, BPF_MAP_TYPE_RINGBUF);\n\t__uint(max_entries, 4096);\n} faketcp_gen_wk SEC(\".maps\");",
		"#define FAKETCP_GENERATION_CAS_ATTEMPTS 8",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("generation barrier source is missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"} faketcp_generation_gate SEC(\".maps\");",
		"} faketcp_generation_wake SEC(\".maps\");",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("long/truncating generation map alias remains: %q", forbidden)
		}
	}

	poison := sourceSection(t, source,
		"faketcp_generation_poison(struct faketcp_generation_gate_value *gate)",
		"static __always_inline int faketcp_generation_enter")
	if !strings.Contains(poison, "__sync_fetch_and_or(&gate->state, FAKETCP_GENERATION_POISON)") {
		t.Fatal("generation poison is not a sticky atomic state transition")
	}

	enter := sourceSection(t, source,
		"static __always_inline int faketcp_generation_enter(__u64 generation)",
		"static __always_inline void faketcp_generation_exit")
	for _, want := range []string{
		"attempt < FAKETCP_GENERATION_CAS_ATTEMPTS",
		"flags != FAKETCP_GENERATION_OPEN",
		"count == FAKETCP_GENERATION_INFLIGHT_MASK",
		"__sync_val_compare_and_swap(&gate->state, old, old + 1)",
	} {
		if !strings.Contains(enter, want) {
			t.Fatalf("bounded generation entry is missing %q", want)
		}
	}
	if strings.Contains(enter, "__sync_fetch_and_add") {
		t.Fatal("generation entry regained an unbounded fetch-add overflow path")
	}

	exit := sourceSection(t, source,
		"static __always_inline void faketcp_generation_exit(__u64 generation)",
		"faketcp_generation_open(struct faketcp_generation_gate_value *gate")
	for _, want := range []string{
		"old = __sync_fetch_and_sub(&gate->state, 1)",
		"count == 0 || gate->generation != generation",
		"count != 1 || flags != (FAKETCP_GENERATION_SEALED",
		"bpf_ringbuf_output(&faketcp_gen_wk, &wake",
		"FAKETCP_GENERATION_SEALED);",
	} {
		if !strings.Contains(exit, want) {
			t.Fatalf("generation exit/wake contract is missing %q", want)
		}
	}
	ringOutput := strings.Index(exit, "bpf_ringbuf_output(&faketcp_gen_wk, &wake")
	if ringOutput < 0 || strings.Contains(exit[ringOutput:], "faketcp_generation_poison") {
		t.Fatal("ring-buffer wake failure became poison instead of retryable quarantine")
	}

	closeBody := sourceSection(t, source,
		"faketcp_generation_close(struct faketcp_generation_gate_value *gate",
		"SEC(\"classifier/faketcp_generation_control\")")
	bind := strings.Index(closeBody, "__sync_val_compare_and_swap(&gate->generation, 0, generation)")
	terminalClose := strings.Index(closeBody, "&gate->state, 0,\n\t\t\t\t    FAKETCP_GENERATION_SEALED")
	sealOpen := strings.Index(closeBody, "next = FAKETCP_GENERATION_SEALED | count")
	retryIdle := strings.Index(closeBody, "&gate->state, old,\n\t\t\t\t    FAKETCP_GENERATION_SEALED")
	if bind < 0 || terminalClose < 0 || sealOpen < 0 || retryIdle < 0 ||
		!(bind < terminalClose && terminalClose < sealOpen && sealOpen < retryIdle) {
		t.Fatal("CLOSE must bind identity, terminally seal unopened state, seal OPEN, and clear a drained wake on retry")
	}

	if got := strings.Count(source, "bpf_map_lookup_elem(&faketcp_managed_if_map"); got != 1 {
		t.Fatalf("managed-interface policy lookup sites=%d, want one guarded site", got)
	}
	if got := strings.Count(source, "bpf_map_lookup_elem(&faketcp_managed_port_map"); got != 1 {
		t.Fatalf("managed-port policy lookup sites=%d, want one guarded site", got)
	}
	if got := strings.Count(source, "bpf_map_lookup_elem(&faketcp_control_policy_map"); got != 1 {
		t.Fatalf("control-policy lookup sites=%d, want one guarded site", got)
	}

	controlInner := sourceSection(t, source,
		"faketcp_admit_control_event_inner(const struct faketcp_session_key",
		"faketcp_admit_control_event(const struct faketcp_session_key")
	controlWrapper := sourceSection(t, source,
		"faketcp_admit_control_event(const struct faketcp_session_key",
		"static __always_inline int faketcp_emit_event")
	assertGenerationWrapper(t, controlWrapper,
		"faketcp_generation_enter(session->generation)",
		"faketcp_admit_control_event_inner(",
		"faketcp_generation_exit(session->generation)")
	if !strings.Contains(controlInner, "bpf_map_lookup_elem(&faketcp_control_policy_map") ||
		strings.Contains(controlWrapper, "bpf_map_lookup_elem(&faketcp_control_policy_map") {
		t.Fatal("control-policy lookup is not wholly inside the guarded control-admit body")
	}

	xdpBody := sourceSection(t, source,
		"faketcp_xdp_ingress_body(struct xdp_md *xdp, __u64 generation)",
		"SEC(\"xdp\")")
	xdpWrapper := sourceSection(t, source,
		"int wg_mix_faketcp_ingress(struct xdp_md *xdp)",
		"#endif")
	assertGenerationWrapper(t, xdpWrapper,
		"faketcp_generation_enter(generation)",
		"faketcp_xdp_ingress_body(xdp, generation)",
		"faketcp_generation_exit(generation)")
	for _, guarded := range []string{"faketcp_xdp_managed_interface(", "faketcp_xdp_managed_port("} {
		if !strings.Contains(xdpBody, guarded) {
			t.Fatalf("XDP guarded body is missing %q", guarded)
		}
	}
	for label, body := range map[string]string{"control": controlInner, "XDP": xdpBody} {
		if strings.Contains(body, "faketcp_generation_enter") ||
			strings.Contains(body, "faketcp_generation_exit") ||
			strings.Contains(body, "bpf_tail_call(") {
			t.Fatalf("%s guarded body can bypass or carry a live token through a tail call", label)
		}
	}

	generationHelpers := sourceSection(t, source,
		"faketcp_generation_poison(struct faketcp_generation_gate_value *gate)",
		"faketcp_bind_runtime_identity(const struct faketcp_session_key")
	for _, forbidden := range []string{"BPF_MAP_TYPE_PERCPU", "bpf_spin_lock", "bpf_usleep", "bpf_loop("} {
		if strings.Contains(generationHelpers, forbidden) {
			t.Fatalf("generation barrier regained a snapshot/spin/sleep fallback through %q", forbidden)
		}
	}
}

func assertGenerationWrapper(t *testing.T, wrapper, enter, body, exit string) {
	t.Helper()
	enterAt := strings.Index(wrapper, enter)
	bodyAt := strings.Index(wrapper, body)
	exitAt := strings.Index(wrapper, exit)
	if enterAt < 0 || bodyAt < 0 || exitAt < 0 || !(enterAt < bodyAt && bodyAt < exitAt) {
		t.Fatalf("generation wrapper order is incomplete: enter=%d body=%d exit=%d", enterAt, bodyAt, exitAt)
	}
	if strings.Count(wrapper, enter) != 1 || strings.Count(wrapper, body) != 1 ||
		strings.Count(wrapper, exit) != 1 {
		t.Fatal("generation wrapper must have exactly one enter/body/exit path")
	}
}

func TestFakeTCPGenerationBarrierUserspaceAndLifecycleContract(t *testing.T) {
	barrierBytes, err := os.ReadFile("faketcp_generation_barrier_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	barrier := string(barrierBytes)
	bind := sourceSection(t, barrier,
		"func (barrier *liveFakeTCPGenerationBarrier) BindCollection(",
		"func liveFakeTCPGenerationMap(")
	if strings.Count(bind, "ctx.Err()") != 2 {
		t.Fatal("collection binding must recheck cancellation after taking the barrier mutex")
	}
	validation := sourceSection(t, barrier,
		"func validateLiveFakeTCPGenerationControl(",
		"func (barrier *liveFakeTCPGenerationBarrier) AssertInactive(")
	for _, want := range []string{
		"make(map[ebpf.MapID]struct{}, 3)",
		"info.MapIDs()",
		"info.Type != ebpf.SchedCLS",
		"len(ids) != 3 || len(expected) != 3",
	} {
		if !strings.Contains(validation, want) {
			t.Fatalf("live control-program identity check is missing %q", want)
		}
	}
	quiesce := sourceSection(t, barrier,
		"func (barrier *liveFakeTCPGenerationBarrier) Quiesce(",
		"func (barrier *liveFakeTCPGenerationBarrier) lock(")
	closeAt := strings.Index(quiesce, "runLocked(abi.FakeTCPGenerationControlClose)")
	wakeAt := strings.Index(quiesce, "readWakeLocked(ctx)")
	confirmAt := strings.Index(quiesce, "expectLocked(\"confirm CLOSE\"")
	verifyAt := strings.LastIndex(quiesce, "verifyIdleLocked()")
	if closeAt < 0 || wakeAt < 0 || confirmAt < 0 || verifyAt < 0 ||
		!(closeAt < wakeAt && wakeAt < confirmAt && confirmAt < verifyAt) {
		t.Fatal("userspace treated wake as proof instead of CLOSE+reread confirmation")
	}
	readerStart := strings.Index(barrier,
		"func (barrier *liveFakeTCPGenerationBarrier) readWakeLocked(")
	if readerStart < 0 {
		t.Fatal("wake reader is missing")
	}
	reader := barrier[readerStart:]
	for _, want := range []string{"SetDeadline(deadline)", "context.AfterFunc(ctx", "reader.Close()"} {
		if !strings.Contains(reader, want) {
			t.Fatalf("bounded/cancelable wake wait is missing %q", want)
		}
	}

	manifestBytes, err := os.ReadFile("experimental_manifest_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(manifestBytes)
	for _, want := range []string{
		`{name: "faketcp_gen_gt", mapType: ebpf.Array, keySize: 4, valueSize: 16, maxEntries: 1, flags: unix.BPF_F_RDONLY}`,
		`{name: "faketcp_gen_wk", mapType: ebpf.RingBuf, maxEntries: 4096}`,
		`name: "wg_faketcp_generation_control", sectionName: "classifier/faketcp_generation_control"`,
	} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("experimental manifest is missing exact barrier resource %q", want)
		}
	}

	runtimeBytes, err := os.ReadFile("experimental_runtime_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	runtimeSource := string(runtimeBytes)
	commit := sourceSection(t, runtimeSource,
		"func (build *experimentalRuntimeBuild) commitAttachedCore(",
		"func (build *experimentalRuntimeBuild) commit()")
	stageAt := strings.Index(commit, "build.claim.Stage(")
	activateAt := strings.Index(commit, "build.claim.Activate(")
	selectorAt := strings.Index(commit, "build.coreStage.CommitControl()")
	if stageAt < 0 || activateAt < 0 || selectorAt < 0 || !(stageAt < activateAt && activateAt < selectorAt) {
		t.Fatal("runtime activation is not Stage -> barrier OPEN -> selector commit")
	}
	cleanup := sourceSection(t, runtimeSource,
		"func (build *experimentalRuntimeBuild) cleanupUncommitted()",
		"func (build *experimentalRuntimeBuild) failCommitted(")
	deactivateAt := strings.Index(cleanup, "build.coreStage.Deactivate()")
	rollbackAt := strings.Index(cleanup, "build.claim.Rollback(")
	detachAt := strings.Index(cleanup, "build.xdpStage.Close()")
	if deactivateAt < 0 || rollbackAt < 0 || detachAt < 0 ||
		!(deactivateAt < rollbackAt && rollbackAt < detachAt) {
		t.Fatal("failed-build cleanup does not deactivate, quiesce/rollback while attached, then detach")
	}
	runtimeClose := sourceSection(t, runtimeSource,
		"func (runtime *ExperimentalFakeTCPRuntime) Close() error",
		"type experimentalRuntimeCloser interface")
	deactivateAt = strings.Index(runtimeClose, "core.Deactivate()")
	quiesceAt := strings.Index(runtimeClose, "isolation.Quiesce(")
	detachAt = strings.Index(runtimeClose, `wrapExperimentalRuntimeClose("XDP links", xdp)`)
	if deactivateAt < 0 || quiesceAt < 0 || detachAt < 0 ||
		!(deactivateAt < quiesceAt && quiesceAt < detachAt) {
		t.Fatal("runtime Close does not deactivate selector, quiesce while attached, then detach")
	}

	policyBytes, err := os.ReadFile("faketcp_policy_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	rollback := sourceSection(t, string(policyBytes),
		"func rollbackFakeTCPPolicyOperationsLocked(",
		"func rollbackFakeTCPPolicyPhase(")
	quiesceAt = strings.Index(rollback, "transaction.isolation.Quiesce(")
	interfaceAt := strings.Index(rollback, "fakeTCPPolicyPhaseInterface")
	portAt := strings.Index(rollback, "fakeTCPPolicyPhasePort")
	controlAt := strings.Index(rollback, "fakeTCPPolicyPhaseControl")
	if quiesceAt < 0 || interfaceAt < 0 || portAt < 0 || controlAt < 0 ||
		!(quiesceAt < interfaceAt && interfaceAt < portAt && portAt < controlAt) {
		t.Fatal("policy rollback does not quiesce before interface/port/control removal")
	}
}
