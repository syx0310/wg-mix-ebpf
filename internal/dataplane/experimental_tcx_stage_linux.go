//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/syx0310/wg-mix-ebpf/internal/control"
)

// experimentalTCXOwnedLink is an exact kernel bpf_link owner. Unlike classic
// TC filter handles, closing this FD cannot delete a foreign program which
// raced into the same priority/handle between userspace inspection and
// deletion.
type experimentalTCXOwnedLink interface {
	Close() error
}

type experimentalTCXRuntime struct {
	attach func(
		int,
		experimentalProgramResource,
		ebpf.AttachType,
	) (experimentalTCXOwnedLink, error)
}

var liveExperimentalTCXRuntime = experimentalTCXRuntime{
	attach: func(
		ifindex int,
		resource experimentalProgramResource,
		attachType ebpf.AttachType,
	) (experimentalTCXOwnedLink, error) {
		if resource == nil || resource.kernelProgram() == nil {
			return nil, errors.New("experimental TCX program is nil")
		}
		program := resource.kernelProgram()
		if program.FD() < 0 {
			return nil, errors.New("experimental TCX program is closed")
		}
		return link.AttachTCX(link.TCXOptions{
			Interface: ifindex,
			Program:   program,
			Attach:    attachType,
		})
	},
}

type experimentalTCXAttachment struct {
	ifindex    int
	attachType ebpf.AttachType
	link       experimentalTCXOwnedLink
}

// experimentalTCXStage owns only links created by one activation attempt.
// Successful siblings are pruned after Close; a failed exact link remains
// available for an outer quarantine owner to retry.
type experimentalTCXStage struct {
	mu sync.Mutex

	attachments []experimentalTCXAttachment
	done        bool
}

func stageLiveExperimentalTC(
	ctx context.Context,
	state *control.State,
	ingress experimentalProgramResource,
	egress experimentalProgramResource,
	commit func() error,
) (experimentalTCStageOwner, error) {
	return stageExperimentalTCX(
		ctx,
		state,
		ingress,
		egress,
		commit,
		liveExperimentalTCXRuntime,
	)
}

func stageExperimentalTCX(
	ctx context.Context,
	state *control.State,
	ingress experimentalProgramResource,
	egress experimentalProgramResource,
	commit func() error,
	runtime experimentalTCXRuntime,
) (*experimentalTCXStage, error) {
	if ctx == nil {
		return nil, errors.New("stage experimental TCX core: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errors.New("stage experimental TCX core: attach state is nil")
	}
	if commit == nil {
		return nil, errors.New("stage experimental TCX core: activation callback is nil")
	}
	if runtime.attach == nil {
		return nil, errors.New("stage experimental TCX core: attach backend is nil")
	}
	if ingress == nil || egress == nil {
		return nil, errors.New("stage experimental TCX core: ingress and egress programs are required")
	}
	ifindexes, err := activeAttachIfindexes(state)
	if err != nil {
		return nil, fmt.Errorf("stage experimental TCX core: derive interfaces: %w", err)
	}
	if len(ifindexes) == 0 {
		return nil, errors.New("stage experimental TCX core: no attachable interfaces")
	}

	stage := &experimentalTCXStage{}
	fail := func(err error) (*experimentalTCXStage, error) {
		if len(stage.attachments) == 0 {
			return nil, err
		}
		return stage, err
	}
	for _, ifindex := range ifindexes {
		for _, request := range []struct {
			attachType ebpf.AttachType
			program    experimentalProgramResource
			label      string
		}{
			{ebpf.AttachTCXIngress, ingress, "ingress"},
			{ebpf.AttachTCXEgress, egress, "egress"},
		} {
			if err := ctx.Err(); err != nil {
				return fail(err)
			}
			owned, err := runtime.attach(ifindex, request.program, request.attachType)
			if err != nil {
				return fail(fmt.Errorf(
					"attach experimental TCX %s on ifindex %d: %w",
					request.label, ifindex, err,
				))
			}
			if owned == nil {
				return fail(fmt.Errorf(
					"attach experimental TCX %s on ifindex %d returned nil owner",
					request.label, ifindex,
				))
			}
			stage.attachments = append(stage.attachments, experimentalTCXAttachment{
				ifindex: ifindex, attachType: request.attachType, link: owned,
			})
		}
	}
	if err := ctx.Err(); err != nil {
		return stage, err
	}
	if err := commit(); err != nil {
		return stage, fmt.Errorf("activate attached experimental TCX programs: %w", err)
	}
	return stage, nil
}

func (stage *experimentalTCXStage) Close() error {
	if stage == nil {
		return nil
	}
	stage.mu.Lock()
	defer stage.mu.Unlock()
	if stage.done {
		return nil
	}
	var errs []error
	remaining := make([]experimentalTCXAttachment, 0, len(stage.attachments))
	for index := len(stage.attachments) - 1; index >= 0; index-- {
		attachment := stage.attachments[index]
		if err := attachment.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf(
				"close experimental TCX link on ifindex %d attach type %s: %w",
				attachment.ifindex, attachment.attachType, err,
			))
			remaining = append([]experimentalTCXAttachment{attachment}, remaining...)
		}
	}
	stage.attachments = remaining
	stage.done = len(remaining) == 0
	return errors.Join(errs...)
}
