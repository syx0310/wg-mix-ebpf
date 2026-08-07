//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	ciliumlink "github.com/cilium/ebpf/link"
)

const exactTCXBackend = "tcx"

type exactTCXDirection string

const (
	exactTCXIngress exactTCXDirection = "ingress"
	exactTCXEgress  exactTCXDirection = "egress"
)

type exactTCXProgram struct {
	id     uint32
	kernel *ebpf.Program
}

type exactTCXBinding struct {
	Backend    string            `json:"backend"`
	IfIndex    int               `json:"ifindex"`
	Direction  exactTCXDirection `json:"direction"`
	AttachType uint32            `json:"attach_type"`
	PinName    string            `json:"pin_name"`
	LinkID     uint32            `json:"link_id"`
	ProgramID  uint32            `json:"program_id"`
}

type exactTCXLinkIdentity struct {
	IfIndex   int
	Attach    ebpf.AttachType
	LinkID    uint32
	ProgramID uint32
}

type exactTCXKernelLink interface {
	Identity() (exactTCXLinkIdentity, error)
	Pin(string) error
	CompareUpdate(next, previous exactTCXProgram) error
	Detach() error
	Unpin() error
	Close() error
}

type exactTCXRuntime struct {
	query      func(int, ebpf.AttachType) (exactTCXQuery, error)
	attach     func(int, ebpf.AttachType, uint64, exactTCXProgram) (exactTCXKernelLink, error)
	loadPinned func(string) (exactTCXKernelLink, error)
}

type exactTCXQueryProgram struct {
	LinkID    uint32
	ProgramID uint32
}

type exactTCXQuery struct {
	Revision uint64
	Programs []exactTCXQueryProgram
}

type liveExactTCXLink struct {
	link ciliumlink.Link
}

type exactTCXLinkUpdater interface {
	UpdateArgs(ciliumlink.RawLinkUpdateOptions) error
}

func (owned *liveExactTCXLink) Identity() (exactTCXLinkIdentity, error) {
	if owned == nil || owned.link == nil {
		return exactTCXLinkIdentity{}, errors.New("TCX link is nil")
	}
	info, err := owned.link.Info()
	if err != nil {
		return exactTCXLinkIdentity{}, fmt.Errorf("inspect TCX link: %w", err)
	}
	tcx := info.TCX()
	if tcx == nil {
		return exactTCXLinkIdentity{}, errors.New("pinned BPF link is not TCX")
	}
	if info.ID == 0 || info.Program == 0 || tcx.Ifindex == 0 {
		return exactTCXLinkIdentity{}, errors.New("kernel returned incomplete TCX link identity")
	}
	return exactTCXLinkIdentity{
		IfIndex:   int(tcx.Ifindex),
		Attach:    ebpf.AttachType(tcx.AttachType),
		LinkID:    uint32(info.ID),
		ProgramID: uint32(info.Program),
	}, nil
}

func (owned *liveExactTCXLink) Pin(path string) error {
	if owned == nil || owned.link == nil {
		return errors.New("TCX link is nil")
	}
	return owned.link.Pin(path)
}

func (owned *liveExactTCXLink) CompareUpdate(next, previous exactTCXProgram) error {
	if owned == nil || owned.link == nil {
		return errors.New("TCX link is nil")
	}
	if next.kernel == nil || previous.kernel == nil {
		return errors.New("TCX compare-update requires live old and new programs")
	}
	updater, ok := owned.link.(exactTCXLinkUpdater)
	if !ok {
		return errors.New("TCX link backend does not expose compare-update")
	}
	return updater.UpdateArgs(ciliumlink.RawLinkUpdateOptions{
		New: next.kernel,
		Old: previous.kernel,
	})
}

func (owned *liveExactTCXLink) Detach() error {
	if owned == nil || owned.link == nil {
		return errors.New("TCX link is nil")
	}
	return owned.link.Detach()
}

func (owned *liveExactTCXLink) Unpin() error {
	if owned == nil || owned.link == nil {
		return errors.New("TCX link is nil")
	}
	return owned.link.Unpin()
}

func (owned *liveExactTCXLink) Close() error {
	if owned == nil || owned.link == nil {
		return nil
	}
	err := owned.link.Close()
	if err == nil {
		owned.link = nil
	}
	return err
}

var liveExactTCXRuntime = exactTCXRuntime{
	query: func(ifindex int, attach ebpf.AttachType) (exactTCXQuery, error) {
		result, err := ciliumlink.QueryPrograms(ciliumlink.QueryOptions{
			Target: ifindex,
			Attach: attach,
		})
		if err != nil {
			return exactTCXQuery{}, err
		}
		if result == nil || result.Revision == 0 {
			return exactTCXQuery{}, errors.New("TCX query did not return a revision fence")
		}
		query := exactTCXQuery{Revision: result.Revision}
		for _, attached := range result.Programs {
			linkID, ok := attached.LinkID()
			if !ok || linkID == 0 || attached.ID == 0 {
				return exactTCXQuery{}, errors.New("TCX query did not return exact link identities")
			}
			query.Programs = append(query.Programs, exactTCXQueryProgram{
				LinkID: uint32(linkID), ProgramID: uint32(attached.ID),
			})
		}
		return query, nil
	},
	attach: func(
		ifindex int,
		attach ebpf.AttachType,
		revision uint64,
		program exactTCXProgram,
	) (exactTCXKernelLink, error) {
		if program.kernel == nil || program.kernel.FD() < 0 {
			return nil, errors.New("TCX program is unavailable")
		}
		owned, err := ciliumlink.AttachTCX(ciliumlink.TCXOptions{
			Interface:        ifindex,
			Program:          program.kernel,
			Attach:           attach,
			Anchor:           ciliumlink.Head(),
			ExpectedRevision: revision,
		})
		if err != nil {
			return nil, err
		}
		return &liveExactTCXLink{link: owned}, nil
	},
	loadPinned: func(path string) (exactTCXKernelLink, error) {
		owned, err := ciliumlink.LoadPinnedLink(path, nil)
		if err != nil {
			return nil, err
		}
		return &liveExactTCXLink{link: owned}, nil
	},
}

type exactTCXJournalOperation string

const (
	exactTCXJournalAttach exactTCXJournalOperation = "attach"
	exactTCXJournalUpdate exactTCXJournalOperation = "update"
)

type exactTCXJournalIntent struct {
	Operation exactTCXJournalOperation
	Active    *exactTCXBinding
	Desired   exactTCXBinding
}

type exactTCXJournal struct {
	persistIntent func(exactTCXJournalIntent) error
	persistActive func(exactTCXBinding, exactTCXJournalIntent) error
}

type exactTCXAttachment struct {
	mu sync.Mutex

	runtime   exactTCXRuntime
	link      exactTCXKernelLink
	binding   exactTCXBinding
	pinPath   string
	pinned    bool
	committed bool
	detached  bool
	closed    bool
}

func exactTCXPinName(ifindex int, direction exactTCXDirection) string {
	return fmt.Sprintf("tcx-link-%010d-%s", ifindex, direction)
}

func exactTCXOwnerKey(binding exactTCXBinding) string {
	return fmt.Sprintf("%010d/%s", binding.IfIndex, binding.Direction)
}

func parseExactTCXPinName(name string) (int, exactTCXDirection, bool) {
	const prefix = "tcx-link-"
	if filepath.Base(name) != name || !strings.HasPrefix(name, prefix) {
		return 0, "", false
	}
	remainder := strings.TrimPrefix(name, prefix)
	if len(remainder) <= 11 || remainder[10] != '-' {
		return 0, "", false
	}
	value, err := strconv.ParseUint(remainder[:10], 10, 32)
	if err != nil || value == 0 || value > uint64(^uint(0)>>1) {
		return 0, "", false
	}
	direction := exactTCXDirection(remainder[11:])
	if _, err := exactTCXAttachType(direction); err != nil {
		return 0, "", false
	}
	ifindex := int(value)
	if exactTCXPinName(ifindex, direction) != name {
		return 0, "", false
	}
	return ifindex, direction, true
}

func exactTCXAttachType(direction exactTCXDirection) (ebpf.AttachType, error) {
	switch direction {
	case exactTCXIngress:
		return ebpf.AttachTCXIngress, nil
	case exactTCXEgress:
		return ebpf.AttachTCXEgress, nil
	default:
		return ebpf.AttachNone, fmt.Errorf("invalid TCX direction %q", direction)
	}
}

func validateExactTCXBinding(binding exactTCXBinding, requireLinkID bool) error {
	if binding.Backend != exactTCXBackend {
		return fmt.Errorf("invalid TCX backend %q", binding.Backend)
	}
	if binding.IfIndex <= 0 || uint64(binding.IfIndex) > math.MaxUint32 || binding.ProgramID == 0 {
		return errors.New("TCX binding requires a positive ifindex and program ID")
	}
	if requireLinkID && binding.LinkID == 0 {
		return errors.New("active TCX binding requires a non-zero link ID")
	}
	if _, err := exactTCXAttachType(binding.Direction); err != nil {
		return err
	}
	attach, _ := exactTCXAttachType(binding.Direction)
	if binding.AttachType != uint32(attach) {
		return fmt.Errorf(
			"TCX binding attach type %d, want %d for %s",
			binding.AttachType, attach, binding.Direction,
		)
	}
	wantName := exactTCXPinName(binding.IfIndex, binding.Direction)
	if binding.PinName != wantName || filepath.Base(binding.PinName) != binding.PinName {
		return fmt.Errorf("TCX binding pin name %q, want %q", binding.PinName, wantName)
	}
	return nil
}

func validateExactTCXPinPath(binding exactTCXBinding, pinPath string) error {
	if pinPath == "" || !filepath.IsAbs(pinPath) || filepath.Clean(pinPath) != pinPath {
		return fmt.Errorf("TCX pin path %q is not a clean absolute path", pinPath)
	}
	if filepath.Dir(pinPath) == string(filepath.Separator) {
		return errors.New("TCX pin path must be inside a dedicated directory")
	}
	if filepath.Base(pinPath) != binding.PinName {
		return fmt.Errorf("TCX pin path base %q, want %q", filepath.Base(pinPath), binding.PinName)
	}
	return nil
}

func validateExactTCXRuntime(runtime exactTCXRuntime) error {
	if runtime.query == nil || runtime.attach == nil || runtime.loadPinned == nil {
		return errors.New("exact TCX runtime is incomplete")
	}
	return nil
}

func stageExactTCXAttachment(
	ctx context.Context,
	binding exactTCXBinding,
	pinPath string,
	program exactTCXProgram,
	journal exactTCXJournal,
	runtime exactTCXRuntime,
) (*exactTCXAttachment, error) {
	if ctx == nil {
		return nil, errors.New("stage exact TCX attachment: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateExactTCXBinding(binding, false); err != nil {
		return nil, err
	}
	if binding.LinkID != 0 {
		return nil, errors.New("new TCX attachment intent must not predict a link ID")
	}
	if program.id == 0 || program.id != binding.ProgramID {
		return nil, errors.New("TCX program identity does not match desired binding")
	}
	if err := validateExactTCXPinPath(binding, pinPath); err != nil {
		return nil, err
	}
	if err := validateExactTCXRuntime(runtime); err != nil {
		return nil, err
	}
	if journal.persistIntent == nil || journal.persistActive == nil {
		return nil, errors.New("exact TCX attachment requires durable journal callbacks")
	}
	attach, err := exactTCXAttachType(binding.Direction)
	if err != nil {
		return nil, err
	}
	// Query is the read-only capability gate. An unsupported result here is
	// the only point at which a caller may choose a compatibility backend:
	// no TCX journal intent or kernel attachment exists yet. The returned
	// revision also fences the later attach across journal persistence.
	query, err := runtime.query(binding.IfIndex, attach)
	if err != nil {
		return nil, fmt.Errorf("query TCX revision fence: %w", err)
	}
	if err := validateExactTCXQuery(query); err != nil {
		return nil, fmt.Errorf("validate TCX revision fence: %w", err)
	}
	intent := exactTCXJournalIntent{
		Operation: exactTCXJournalAttach,
		Desired:   binding,
	}
	if err := journal.persistIntent(intent); err != nil {
		return nil, fmt.Errorf("persist TCX attach intent: %w", err)
	}
	ownedLink, err := runtime.attach(binding.IfIndex, attach, query.Revision, program)
	if err != nil {
		return nil, fmt.Errorf("attach exact TCX link: %w", err)
	}
	owner := &exactTCXAttachment{
		runtime: runtime,
		link:    ownedLink,
		binding: binding,
		pinPath: pinPath,
	}
	fail := func(cause error) (*exactTCXAttachment, error) {
		if owner.link == nil {
			return nil, cause
		}
		// Once the deterministic pin exists, mutating owner intent covers it
		// and restart recovery must retain it. Before the pin exists, no
		// durable identity can recover this particular link, so detach the
		// exact FD immediately instead of leaking an unpinned attachment.
		if owner.pinned {
			return owner, cause
		}
		return nil, errors.Join(cause, owner.Rollback())
	}
	if ownedLink == nil {
		return fail(errors.New("attach exact TCX link returned nil ownership"))
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	identity, err := ownedLink.Identity()
	if err != nil {
		return fail(fmt.Errorf("inspect attached TCX link: %w", err))
	}
	if err := validateExactTCXIdentity(binding, identity, false); err != nil {
		return fail(err)
	}
	owner.binding.LinkID = identity.LinkID
	if err := ownedLink.Pin(pinPath); err != nil {
		return fail(fmt.Errorf("pin exact TCX link: %w", err))
	}
	owner.pinned = true
	if err := journal.persistActive(owner.binding, intent); err != nil {
		return fail(fmt.Errorf("persist active TCX link identity: %w", err))
	}
	owner.committed = true
	return owner, nil
}

func loadExactTCXAttachment(
	binding exactTCXBinding,
	pinPath string,
	runtime exactTCXRuntime,
) (*exactTCXAttachment, error) {
	if err := validateExactTCXBinding(binding, true); err != nil {
		return nil, err
	}
	owner, observed, err := observePinnedExactTCXAttachment(
		binding,
		pinPath,
		[]uint32{binding.ProgramID},
		runtime,
	)
	if err != nil {
		return nil, err
	}
	if !observed.Attached {
		return nil, errors.Join(
			errors.New("pinned exact TCX link is detached"),
			owner.link.Close(),
		)
	}
	owner.committed = true
	return owner, nil
}

func observePinnedExactTCXAttachment(
	template exactTCXBinding,
	pinPath string,
	allowedProgramIDs []uint32,
	runtime exactTCXRuntime,
) (*exactTCXAttachment, *exactTCXObservation, error) {
	if err := validateExactTCXBinding(template, false); err != nil {
		return nil, nil, err
	}
	if err := validateExactTCXPinPath(template, pinPath); err != nil {
		return nil, nil, err
	}
	if err := validateExactTCXRuntime(runtime); err != nil {
		return nil, nil, err
	}
	allowed := make(map[uint32]struct{}, len(allowedProgramIDs))
	for _, id := range allowedProgramIDs {
		if id == 0 {
			return nil, nil, errors.New("exact TCX observation has a zero allowed program ID")
		}
		allowed[id] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, nil, errors.New("exact TCX observation has no allowed program IDs")
	}
	ownedLink, err := runtime.loadPinned(pinPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load pinned exact TCX link: %w", err)
	}
	if ownedLink == nil {
		return nil, nil, errors.New("load pinned exact TCX link returned nil ownership")
	}
	closeOnError := func(err error) (*exactTCXAttachment, *exactTCXObservation, error) {
		return nil, nil, errors.Join(err, ownedLink.Close())
	}
	identity, err := ownedLink.Identity()
	if err != nil {
		return closeOnError(fmt.Errorf("inspect pinned exact TCX link: %w", err))
	}
	observedBinding := template
	observedBinding.LinkID = identity.LinkID
	observedBinding.ProgramID = identity.ProgramID
	if err := validateExactTCXIdentity(observedBinding, identity, true); err != nil {
		return closeOnError(err)
	}
	if template.LinkID != 0 && identity.LinkID != template.LinkID {
		return closeOnError(fmt.Errorf(
			"TCX link ID %d, owner journal requires %d",
			identity.LinkID, template.LinkID,
		))
	}
	if _, ok := allowed[identity.ProgramID]; !ok {
		return closeOnError(fmt.Errorf(
			"TCX link program ID %d is outside the owner journal old/new set",
			identity.ProgramID,
		))
	}
	attach, err := exactTCXAttachType(template.Direction)
	if err != nil {
		return closeOnError(err)
	}
	query, err := runtime.query(template.IfIndex, attach)
	if err != nil {
		return closeOnError(fmt.Errorf("query pinned exact TCX attachment: %w", err))
	}
	if err := validateExactTCXQuery(query); err != nil {
		return closeOnError(fmt.Errorf("validate pinned exact TCX query: %w", err))
	}
	attached, err := exactTCXQueryContains(observedBinding, query)
	if err != nil {
		return closeOnError(err)
	}
	owner := &exactTCXAttachment{
		runtime:   runtime,
		link:      ownedLink,
		binding:   observedBinding,
		pinPath:   pinPath,
		pinned:    true,
		committed: template.LinkID != 0,
		detached:  !attached,
	}
	observation := &exactTCXObservation{
		Binding:  observedBinding,
		Attached: attached,
	}
	return owner, observation, nil
}

func exactTCXQueryContains(binding exactTCXBinding, query exactTCXQuery) (bool, error) {
	if query.Revision == 0 {
		return false, errors.New("TCX query has no revision fence")
	}
	found := false
	for _, program := range query.Programs {
		if program.LinkID != binding.LinkID {
			continue
		}
		if found {
			return false, fmt.Errorf("TCX query repeats link ID %d", binding.LinkID)
		}
		found = true
		if program.ProgramID != binding.ProgramID {
			return false, fmt.Errorf(
				"TCX query link ID %d has program ID %d, owner requires %d",
				binding.LinkID, program.ProgramID, binding.ProgramID,
			)
		}
	}
	return found, nil
}

func validateExactTCXIdentity(
	binding exactTCXBinding,
	identity exactTCXLinkIdentity,
	requireRecordedLinkID bool,
) error {
	attach, err := exactTCXAttachType(binding.Direction)
	if err != nil {
		return err
	}
	if identity.IfIndex != binding.IfIndex || identity.Attach != attach {
		return fmt.Errorf(
			"TCX link target changed: ifindex/type=%d/%s, want %d/%s",
			identity.IfIndex, identity.Attach, binding.IfIndex, attach,
		)
	}
	if identity.LinkID == 0 || identity.ProgramID != binding.ProgramID {
		return fmt.Errorf(
			"TCX link identity changed: link/program=%d/%d, want nonzero/%d",
			identity.LinkID, identity.ProgramID, binding.ProgramID,
		)
	}
	if requireRecordedLinkID && identity.LinkID != binding.LinkID {
		return fmt.Errorf("TCX link ID %d, owner journal requires %d", identity.LinkID, binding.LinkID)
	}
	return nil
}

func (owner *exactTCXAttachment) CompareUpdateWithOld(
	previous exactTCXProgram,
	next exactTCXProgram,
	journal exactTCXJournal,
) error {
	if owner == nil {
		return errors.New("update exact TCX attachment: owner is nil")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed || owner.link == nil || !owner.pinned || !owner.committed || owner.detached {
		return errors.New("update exact TCX attachment: owner is not active")
	}
	if previous.id != owner.binding.ProgramID || next.id == 0 || next.id == previous.id {
		return errors.New("TCX update program identities do not match active/desired state")
	}
	if journal.persistIntent == nil || journal.persistActive == nil {
		return errors.New("exact TCX update requires durable journal callbacks")
	}
	active := owner.binding
	desired := owner.binding
	desired.ProgramID = next.id
	intent := exactTCXJournalIntent{
		Operation: exactTCXJournalUpdate,
		Active:    &active,
		Desired:   desired,
	}
	if err := journal.persistIntent(intent); err != nil {
		return fmt.Errorf("persist TCX update intent: %w", err)
	}
	owner.committed = false
	if err := owner.link.CompareUpdate(next, previous); err != nil {
		return fmt.Errorf("compare-update exact TCX link: %w", err)
	}
	identity, err := owner.link.Identity()
	if err != nil {
		return fmt.Errorf("inspect updated exact TCX link: %w", err)
	}
	if err := validateExactTCXIdentity(desired, identity, true); err != nil {
		return err
	}
	owner.binding = desired
	if err := journal.persistActive(desired, intent); err != nil {
		return fmt.Errorf("persist updated active TCX identity: %w", err)
	}
	owner.committed = true
	return nil
}

func (owner *exactTCXAttachment) Release() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return nil
	}
	if !owner.pinned || owner.detached {
		return errors.New("cannot release a TCX owner before its exact pin exists")
	}
	// A pinned owner is always journal-covered: stageExactTCXAttachment writes
	// attach intent before creating the link, and CompareUpdateWithOld writes
	// update intent before BPF_LINK_UPDATE. Closing this process-local FD is
	// therefore safe even when the final active-record persist failed; restart
	// recovery reloads the exact pinned link and classifies old/new state.
	if err := owner.link.Close(); err != nil {
		return err
	}
	owner.link = nil
	owner.closed = true
	return nil
}

// Rollback detaches the exact bpf_link FD before removing its pin. It never
// addresses a TC slot by ifindex/priority/handle and therefore cannot delete a
// foreign link which raced into the same TCX direction. It also never touches
// clsact, which is not used by TCX.
func (owner *exactTCXAttachment) Rollback() error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return nil
	}
	if owner.link == nil {
		return errors.New("exact TCX rollback lost its link FD")
	}
	if !owner.detached {
		if err := owner.link.Detach(); err != nil {
			return fmt.Errorf("detach exact TCX link %d: %w", owner.binding.LinkID, err)
		}
		owner.detached = true
	}
	if owner.pinned {
		if err := owner.link.Unpin(); err != nil {
			return fmt.Errorf("unpin detached exact TCX link %d: %w", owner.binding.LinkID, err)
		}
		owner.pinned = false
	}
	if err := owner.link.Close(); err != nil {
		return fmt.Errorf("close detached exact TCX link %d: %w", owner.binding.LinkID, err)
	}
	owner.link = nil
	owner.closed = true
	return nil
}

type exactTCXRecoveryAction string

const (
	exactTCXRecoveryRetryAttach exactTCXRecoveryAction = "retry_attach"
	exactTCXRecoveryDiscardPin  exactTCXRecoveryAction = "discard_detached_pin"
	exactTCXRecoveryPublish     exactTCXRecoveryAction = "publish_active"
	exactTCXRecoveryRetryUpdate exactTCXRecoveryAction = "retry_compare_update"
)

func classifyExactTCXRecovery(
	intent exactTCXJournalIntent,
	observed *exactTCXObservation,
) (exactTCXRecoveryAction, error) {
	if err := validateExactTCXBinding(intent.Desired, false); err != nil {
		return "", err
	}
	switch intent.Operation {
	case exactTCXJournalAttach:
		if intent.Active != nil || intent.Desired.LinkID != 0 {
			return "", errors.New("TCX attach intent has an active or predicted link ID")
		}
		if observed == nil {
			return exactTCXRecoveryRetryAttach, nil
		}
		if err := validateExactTCXBinding(observed.Binding, true); err != nil {
			return "", err
		}
		if !sameExactTCXSlot(observed.Binding, intent.Desired) ||
			observed.Binding.ProgramID != intent.Desired.ProgramID {
			return "", errors.New("pinned TCX link is outside attach journal intent")
		}
		if !observed.Attached {
			return exactTCXRecoveryDiscardPin, nil
		}
		return exactTCXRecoveryPublish, nil
	case exactTCXJournalUpdate:
		if intent.Active == nil {
			return "", errors.New("TCX update intent has no active binding")
		}
		if err := validateExactTCXBinding(*intent.Active, true); err != nil {
			return "", err
		}
		if intent.Desired.LinkID != intent.Active.LinkID ||
			!sameExactTCXSlot(intent.Desired, *intent.Active) ||
			intent.Desired.ProgramID == intent.Active.ProgramID {
			return "", errors.New("TCX update intent changes link identity or not its program")
		}
		if observed == nil {
			return "", errors.New("owned TCX pin disappeared during update")
		}
		if err := validateExactTCXBinding(observed.Binding, true); err != nil {
			return "", err
		}
		if observed.Binding.LinkID != intent.Active.LinkID ||
			!sameExactTCXSlot(observed.Binding, *intent.Active) {
			return "", errors.New("pinned TCX link identity changed during update")
		}
		if !observed.Attached {
			return "", errors.New("owned TCX link detached during update")
		}
		switch observed.Binding.ProgramID {
		case intent.Active.ProgramID:
			return exactTCXRecoveryRetryUpdate, nil
		case intent.Desired.ProgramID:
			return exactTCXRecoveryPublish, nil
		default:
			return "", fmt.Errorf(
				"owned TCX link has program ID %d outside journal old/new set",
				observed.Binding.ProgramID,
			)
		}
	default:
		return "", fmt.Errorf("unsupported TCX journal operation %q", intent.Operation)
	}
}

type exactTCXObservation struct {
	Binding  exactTCXBinding
	Attached bool
}

func sameExactTCXSlot(left, right exactTCXBinding) bool {
	return left.Backend == right.Backend &&
		left.IfIndex == right.IfIndex &&
		left.Direction == right.Direction &&
		left.AttachType == right.AttachType &&
		left.PinName == right.PinName
}

// classic fallback is permitted only before any TCX intent is durable and
// only when cilium/ebpf's feature probe proves TCX unavailable. Permission,
// validation, revision-staleness, and arbitrary syscall failures are not
// capability signals and must fail closed.
func canFallbackFromExactTCX(err error, durableIntent bool) bool {
	return !durableIntent && errors.Is(err, ciliumlink.ErrNotSupported)
}
