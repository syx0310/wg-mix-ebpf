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
	"golang.org/x/sys/unix"
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
	Backend        string            `json:"backend"`
	IfIndex        int               `json:"ifindex"`
	Direction      exactTCXDirection `json:"direction"`
	AttachType     uint32            `json:"attach_type"`
	PinName        string            `json:"pin_name"`
	LinkID         uint32            `json:"link_id"`
	ProgramID      uint32            `json:"program_id"`
	ReplacesLinkID uint32            `json:"replaces_link_id,omitempty"`
	PinPending     bool              `json:"pin_pending,omitempty"`
	Retiring       bool              `json:"retiring,omitempty"`
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
	CompareUpdate(exactTCXLinkUpdate) error
	Detach() error
	Unpin() error
	Close() error
}

type exactTCXLinkUpdate struct {
	New   exactTCXProgram
	Old   exactTCXProgram
	Flags uint32
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
	link exactTCXLiveLink
}

type exactTCXLiveLink interface {
	Pin(string) error
	Unpin() error
	Close() error
	Detach() error
	Info() (*ciliumlink.Info, error)
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
	if info == nil {
		return exactTCXLinkIdentity{}, errors.New("inspect TCX link returned nil info")
	}
	tcx := info.TCX()
	if tcx == nil {
		return exactTCXLinkIdentity{}, errors.New("pinned BPF link is not TCX")
	}
	if info.ID == 0 || info.Program == 0 {
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

func (owned *liveExactTCXLink) CompareUpdate(update exactTCXLinkUpdate) error {
	if owned == nil || owned.link == nil {
		return errors.New("TCX link is nil")
	}
	if update.New.kernel == nil || update.Old.kernel == nil {
		return errors.New("TCX compare-update requires live old and new programs")
	}
	if update.Flags != unix.BPF_F_REPLACE {
		return fmt.Errorf("TCX compare-update flags %#x, want BPF_F_REPLACE", update.Flags)
	}
	updater, ok := owned.link.(exactTCXLinkUpdater)
	if !ok {
		return errors.New("TCX link backend does not expose compare-update")
	}
	return updater.UpdateArgs(ciliumlink.RawLinkUpdateOptions{
		New:   update.New.kernel,
		Old:   update.Old.kernel,
		Flags: update.Flags,
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
	persistIntent   func(exactTCXJournalIntent) error
	persistIdentity func(exactTCXBinding, exactTCXJournalIntent) error
}

type exactTCXAttachment struct {
	mu sync.Mutex

	runtime    exactTCXRuntime
	link       exactTCXKernelLink
	binding    exactTCXBinding
	pinPath    string
	pinned     bool
	recheckPin func() error
	committed  bool
	detached   bool
	closed     bool
}

var retainedUnpinnedExactTCXOwners = struct {
	sync.Mutex
	byPinPath map[string]map[uint32]*exactTCXAttachment
}{byPinPath: make(map[string]map[uint32]*exactTCXAttachment)}

func retainUnpinnedExactTCXOwner(owner *exactTCXAttachment) error {
	if owner == nil || owner.pinPath == "" || owner.pinned || owner.closed || owner.link == nil {
		return errors.New("cannot retain invalid unpinned exact TCX owner")
	}
	retainedUnpinnedExactTCXOwners.Lock()
	defer retainedUnpinnedExactTCXOwners.Unlock()
	owners := retainedUnpinnedExactTCXOwners.byPinPath[owner.pinPath]
	if owners == nil {
		owners = make(map[uint32]*exactTCXAttachment)
		retainedUnpinnedExactTCXOwners.byPinPath[owner.pinPath] = owners
	}
	if previous := owners[owner.binding.LinkID]; previous != nil && previous != owner {
		return fmt.Errorf(
			"another unpinned exact TCX owner already retains link ID %d for %s",
			owner.binding.LinkID,
			owner.pinPath,
		)
	}
	owners[owner.binding.LinkID] = owner
	return nil
}

func retryRetainedUnpinnedExactTCXOwner(pinPath string) error {
	retainedUnpinnedExactTCXOwners.Lock()
	defer retainedUnpinnedExactTCXOwners.Unlock()
	owners := retainedUnpinnedExactTCXOwners.byPinPath[pinPath]
	if len(owners) == 0 {
		return nil
	}
	var cleanupErr error
	for linkID, owner := range owners {
		complete, err := owner.closeUnpinnedAfterFailure()
		cleanupErr = errors.Join(cleanupErr, err)
		if complete {
			delete(owners, linkID)
		}
	}
	if len(owners) != 0 {
		return errors.Join(
			errors.New("retained unpinned exact TCX owner is still live; refusing a duplicate attach"),
			cleanupErr,
		)
	}
	delete(retainedUnpinnedExactTCXOwners.byPinPath, pinPath)
	return cleanupErr
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
	if binding.LinkID != 0 || binding.PinPending || binding.Retiring {
		return nil, errors.New("new TCX attachment intent must not predict a link ID or pending pin")
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
	if journal.persistIntent == nil || journal.persistIdentity == nil {
		return nil, errors.New("exact TCX attachment requires durable journal callbacks")
	}
	if err := retryRetainedUnpinnedExactTCXOwner(pinPath); err != nil {
		return nil, err
	}
	attach, err := exactTCXAttachType(binding.Direction)
	if err != nil {
		return nil, err
	}
	// Query is the read-only capability gate. Unsupported TCX fails before any
	// owner intent or kernel attachment exists. The returned revision also
	// fences the later attach across journal persistence.
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
		// and restart recovery must retain it. Before the pin exists, close the
		// exact unpinned owner or retain its FD in-process until cleanup can be
		// proven complete, so a retry cannot create an untracked duplicate.
		if owner.pinned {
			return owner, cause
		}
		complete, cleanupErr := owner.closeUnpinnedAfterFailure()
		if complete {
			return nil, errors.Join(cause, cleanupErr)
		}
		retainErr := retainUnpinnedExactTCXOwner(owner)
		return nil, errors.Join(cause, cleanupErr, retainErr)
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
	// Persist the exact LinkID before creating the deterministic pin. This
	// closes the crash window where a detached pinned link could otherwise be
	// observed without a journaled identity precise enough to retire it.
	pendingPin := owner.binding
	pendingPin.PinPending = true
	if err := journal.persistIdentity(pendingPin, intent); err != nil {
		return fail(fmt.Errorf("persist exact TCX link identity: %w", err))
	}
	if err := ownedLink.Pin(pinPath); err != nil {
		return fail(fmt.Errorf("pin exact TCX link: %w", err))
	}
	owner.pinned = true
	if err := journal.persistIdentity(owner.binding, intent); err != nil {
		return fail(fmt.Errorf("persist exact TCX pin completion: %w", err))
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
	observedBinding.PinPending = false
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
	attached := false
	switch identity.IfIndex {
	case template.IfIndex:
		if err := validateExactTCXIdentity(observedBinding, identity, true); err != nil {
			return closeOnError(err)
		}
		query, err := runtime.query(template.IfIndex, attach)
		if err != nil {
			return closeOnError(fmt.Errorf("query pinned exact TCX attachment: %w", err))
		}
		if err := validateExactTCXQuery(query); err != nil {
			return closeOnError(fmt.Errorf("validate pinned exact TCX query: %w", err))
		}
		attached, err = exactTCXQueryContains(observedBinding, query)
		if err != nil {
			return closeOnError(err)
		}
		if !attached {
			return closeOnError(fmt.Errorf(
				"active TCX link %d is absent from its original slot query",
				identity.LinkID,
			))
		}
	case 0:
		if template.LinkID == 0 {
			return closeOnError(errors.New(
				"detached TCX pin has no exact journaled link ID",
			))
		}
		// The caller already fenced identity.ProgramID to its explicit allowed
		// old/new set. Validate the observed program just as the attached branch
		// does so a crash after an exact CAS can retire either journaled version
		// of the same detached link ID.
		if err := validateDetachedExactTCXIdentity(observedBinding, identity); err != nil {
			return closeOnError(err)
		}
		absent, err := exactTCXLinkAbsentFromOriginalSlot(template, runtime)
		if err != nil {
			return closeOnError(err)
		}
		if !absent {
			return closeOnError(fmt.Errorf(
				"detached TCX link %d still appears in its original slot",
				template.LinkID,
			))
		}
	default:
		return closeOnError(fmt.Errorf(
			"TCX link target changed: ifindex/type=%d/%s, want active %d/%s or detached 0/%s",
			identity.IfIndex, identity.Attach, template.IfIndex, attach, attach,
		))
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

func exactTCXLinkAbsentFromOriginalSlot(
	binding exactTCXBinding,
	runtime exactTCXRuntime,
) (bool, error) {
	if err := validateExactTCXBinding(binding, true); err != nil {
		return false, err
	}
	if err := validateExactTCXRuntime(runtime); err != nil {
		return false, err
	}
	attach, err := exactTCXAttachType(binding.Direction)
	if err != nil {
		return false, err
	}
	query, err := runtime.query(binding.IfIndex, attach)
	if err != nil {
		// Once an exact pinned link reports detached ifindex=0, a missing
		// original netdevice is also an absence proof for that old slot. A
		// reused ifindex is queried normally and must not contain our LinkID.
		if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
			return true, nil
		}
		return false, fmt.Errorf("query detached TCX link original slot: %w", err)
	}
	if err := validateExactTCXQuery(query); err != nil {
		return false, fmt.Errorf("validate detached TCX link original slot: %w", err)
	}
	present, err := exactTCXQueryContains(binding, query)
	if err != nil {
		return false, err
	}
	return !present, nil
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

func validateDetachedExactTCXIdentity(
	binding exactTCXBinding,
	identity exactTCXLinkIdentity,
) error {
	attach, err := exactTCXAttachType(binding.Direction)
	if err != nil {
		return err
	}
	if binding.LinkID == 0 || identity.IfIndex != 0 || identity.Attach != attach {
		return fmt.Errorf(
			"detached TCX link target changed: ifindex/type=%d/%s, want 0/%s with a journaled link ID",
			identity.IfIndex, identity.Attach, attach,
		)
	}
	if identity.LinkID != binding.LinkID || identity.ProgramID != binding.ProgramID {
		return fmt.Errorf(
			"detached TCX identity changed: link/program=%d/%d, owner requires %d/%d",
			identity.LinkID, identity.ProgramID, binding.LinkID, binding.ProgramID,
		)
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
	if journal.persistIntent == nil || journal.persistIdentity == nil {
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
	if err := owner.link.CompareUpdate(exactTCXLinkUpdate{
		New:   next,
		Old:   previous,
		Flags: unix.BPF_F_REPLACE,
	}); err != nil {
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
	if err := journal.persistIdentity(desired, intent); err != nil {
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
	if !owner.pinned {
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

func (owner *exactTCXAttachment) closeUnpinnedAfterFailure() (bool, error) {
	if owner == nil {
		return true, nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return true, nil
	}
	if owner.pinned || owner.link == nil || owner.binding.LinkID == 0 {
		return false, errors.New("failed exact TCX owner is not an identifiable unpinned link")
	}
	var detachErr error
	if !owner.detached {
		detachErr = owner.link.Detach()
		if detachErr == nil {
			owner.detached = true
		}
	}
	closeErr := owner.link.Close()
	if closeErr == nil {
		owner.link = nil
		owner.closed = true
	}
	absent, queryErr := exactTCXLinkAbsentFromOriginalSlot(owner.binding, owner.runtime)
	if queryErr != nil {
		queryErr = fmt.Errorf("verify failed unpinned exact TCX link %d: %w", owner.binding.LinkID, queryErr)
	} else if !absent {
		queryErr = fmt.Errorf("failed unpinned exact TCX link %d remains attached", owner.binding.LinkID)
	}
	complete := owner.closed && queryErr == nil
	return complete, errors.Join(
		wrapExactTCXCleanupError("detach failed unpinned exact TCX link", detachErr),
		wrapExactTCXCleanupError("close failed unpinned exact TCX link", closeErr),
		queryErr,
	)
}

func wrapExactTCXCleanupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
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
	if owner.pinned && owner.recheckPin != nil {
		if err := owner.recheckPin(); err != nil {
			return fmt.Errorf("recheck exact TCX pin %d before detach: %w", owner.binding.LinkID, err)
		}
	}
	if !owner.detached {
		if err := owner.link.Detach(); err != nil {
			return fmt.Errorf("detach exact TCX link %d: %w", owner.binding.LinkID, err)
		}
		owner.detached = true
	}
	if owner.pinned {
		if owner.recheckPin != nil {
			if err := owner.recheckPin(); err != nil {
				return fmt.Errorf("recheck exact TCX pin %d before unpin: %w", owner.binding.LinkID, err)
			}
		}
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
