package faketcp

import (
	"errors"
	"time"
)

// ErrStartupGuardLeaseMismatch means a caller tried to release an admission
// barrier without presenting the exact lease token for the barrier that is
// currently held. The barrier is deliberately left closed on this error.
var ErrStartupGuardLeaseMismatch = errors.New("startup guard lease does not own the active barrier")

// startupGuardLeaseIdentity is deliberately private. A caller can copy and
// return a token issued by this package, but cannot construct a non-zero token
// that compares equal to an active lease.
type startupGuardLeaseIdentity struct{ _ byte }

// StartupGuardLeaseToken is an opaque, comparable identity. Its zero value is
// never a valid lease token. Callers must not derive policy from the token;
// they may only retain it and pass the complete lease back to Resume.
type StartupGuardLeaseToken struct {
	identity *startupGuardLeaseIdentity
}

// IsZero reports whether the token is the unissued zero value.
func (token StartupGuardLeaseToken) IsZero() bool {
	return token.identity == nil
}

// StartupGuardLease proves which startup-guard admission barrier a Pause call
// observed. Acquired is true only for the call that moved open to draining;
// a call that finds the same barrier already held receives the same non-zero
// Token with Acquired false so a lifecycle-serialised retry can release it
// after independently proving the kernel startup guard absent.
type StartupGuardLease struct {
	Acquired bool
	Token    StartupGuardLeaseToken
}

// NewStartupGuardLease mints a unique lease for a RuntimeStartupGuardPauser
// implementation that is transitioning its own barrier from open to
// draining. A token minted by a caller cannot match another runtime's active
// token and therefore cannot release that runtime's barrier.
func NewStartupGuardLease() StartupGuardLease {
	return StartupGuardLease{
		Acquired: true,
		Token: StartupGuardLeaseToken{
			identity: &startupGuardLeaseIdentity{},
		},
	}
}

func borrowedStartupGuardLease(token StartupGuardLeaseToken) StartupGuardLease {
	return StartupGuardLease{Token: token}
}

func (lease StartupGuardLease) valid() bool {
	return !lease.Token.IsZero()
}

// StartupGuardPausePhase is the observable admission-barrier phase of a
// resident FakeTCP userspace runtime. A pause closes admission before entering
// draining, reaches held only after all admitted work has completed, and may
// then move through resuming back to open.
type StartupGuardPausePhase string

const (
	StartupGuardPausePhaseOpen     StartupGuardPausePhase = "open"
	StartupGuardPausePhaseDraining StartupGuardPausePhase = "draining"
	StartupGuardPausePhaseHeld     StartupGuardPausePhase = "held"
	StartupGuardPausePhaseResuming StartupGuardPausePhase = "resuming"
	StartupGuardPausePhaseStopped  StartupGuardPausePhase = "stopped"
)

// StartupGuardPauseReason explains why admission is in its current phase.
// The value is deliberately typed so status callers do not need to infer
// lifecycle state from error text.
type StartupGuardPauseReason string

const (
	StartupGuardPauseReasonNone            StartupGuardPauseReason = "none"
	StartupGuardPauseReasonStartupGuard    StartupGuardPauseReason = "startup_guard"
	StartupGuardPauseReasonRuntimeStopping StartupGuardPauseReason = "runtime_stopping"
	StartupGuardPauseReasonRuntimeClosed   StartupGuardPauseReason = "runtime_closed"
	StartupGuardPauseReasonRuntimeStopped  StartupGuardPauseReason = "runtime_stopped"
)

// StartupGuardPauseStatus is an immutable snapshot. Since is the time at which
// the current phase began. A zero Since means no concrete owner timestamp is
// available (for example, a status request through a nil owner).
type StartupGuardPauseStatus struct {
	Phase  StartupGuardPausePhase
	Reason StartupGuardPauseReason
	Since  time.Time
}

// RuntimeStartupGuardPauseStatusProvider exposes the pause state without
// coupling status callers to the concrete event-loop implementation.
type RuntimeStartupGuardPauseStatusProvider interface {
	StartupGuardPauseStatus() StartupGuardPauseStatus
}
