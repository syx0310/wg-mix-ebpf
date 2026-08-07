package faketcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	ErrRuntimeStackClosed     = errors.New("faketcp runtime stack is closed")
	ErrRuntimeStopUnavailable = errors.New("faketcp runtime does not support callback-safe stop requests")
)

// RuntimeStack binds the userspace slow path to the kernel generation that
// owns its events map. NewLinuxEventReader must be fully constructed inside
// the generation owner's borrowed-map callback; that callback must return
// before constructing, running, stopping, or closing this stack. Neither this
// stack nor EventReader retains the borrowed raw *ebpf.Map.
//
// Close always completes the slow-path close first (reader, Run join,
// controller/backend) and closes the generation owner last. A callback
// running on Run must call RequestStop, return, and let its owner call Close;
// synchronous callback re-entry into Close would wait for that same Run.
type RuntimeStack struct {
	mu sync.Mutex

	slowPath   RuntimeService
	generation io.Closer
	closeDone  chan struct{}
	closing    bool
	closed     bool
	closeErr   error
}

var _ RuntimeService = (*RuntimeStack)(nil)
var _ RuntimeStopRequester = (*RuntimeStack)(nil)

func NewRuntimeStack(slowPath RuntimeService, generation io.Closer) (*RuntimeStack, error) {
	if interfaceValueIsNil(slowPath) {
		return nil, errors.New("faketcp runtime stack slow path is nil")
	}
	if interfaceValueIsNil(generation) {
		return nil, errors.New("faketcp runtime stack generation owner is nil")
	}
	return &RuntimeStack{
		slowPath: slowPath, generation: generation, closeDone: make(chan struct{}),
	}, nil
}

func (stack *RuntimeStack) Run(ctx context.Context) error {
	if stack == nil {
		return ErrRuntimeStackClosed
	}
	stack.mu.Lock()
	if stack.closing || stack.closed {
		stack.mu.Unlock()
		return ErrRuntimeStackClosed
	}
	slowPath := stack.slowPath
	stack.mu.Unlock()
	return slowPath.Run(ctx)
}

func (stack *RuntimeStack) RequestStop() error {
	if stack == nil {
		return ErrRuntimeStackClosed
	}
	stack.mu.Lock()
	if stack.closing || stack.closed {
		stack.mu.Unlock()
		return ErrRuntimeStackClosed
	}
	stopper, ok := stack.slowPath.(RuntimeStopRequester)
	stack.mu.Unlock()
	if !ok || interfaceValueIsNil(stopper) {
		return ErrRuntimeStopUnavailable
	}
	return stopper.RequestStop()
}

func (stack *RuntimeStack) Close() error {
	if stack == nil {
		return nil
	}
	stack.mu.Lock()
	if stack.closed {
		closeErr := stack.closeErr
		stack.mu.Unlock()
		return closeErr
	}
	if stack.closing {
		closeDone := stack.closeDone
		stack.mu.Unlock()
		<-closeDone
		stack.mu.Lock()
		closeErr := stack.closeErr
		stack.mu.Unlock()
		return closeErr
	}
	stack.closing = true
	slowPath := stack.slowPath
	generation := stack.generation
	stack.mu.Unlock()

	slowPathErr := slowPath.Close()
	generationErr := generation.Close()
	closeErr := errors.Join(
		wrapRuntimeStackCloseError("slow path", slowPathErr),
		wrapRuntimeStackCloseError("generation owner", generationErr),
	)

	stack.mu.Lock()
	stack.closeErr = closeErr
	stack.closed = true
	stack.closing = false
	close(stack.closeDone)
	stack.mu.Unlock()
	return closeErr
}

func wrapRuntimeStackCloseError(resource string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close faketcp runtime stack %s: %w", resource, err)
}
