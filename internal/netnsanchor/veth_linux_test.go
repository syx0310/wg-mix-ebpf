//go:build linux

package netnsanchor

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
)

func testVethClient(role string) clientFlags {
	return clientFlags{
		socket:            "wme-netns-01234567-" + role + "-0123456789abcdef",
		tokenFile:         "/run/wg-mix-ebpf-tests/01234567/secrets/netns-anchor-token",
		runID:             "01234567",
		role:              role,
		expectedDevice:    42,
		expectedInode:     100 + uint64(role[0]),
		expectedAnchorPID: 1000 + int(role[0]),
		expectedAnchorUID: 0,
	}
}

func TestValidateVethPairContractBindsBothAnonymousNamespaces(t *testing.T) {
	left := testVethClient("a")
	right := testVethClient("r")
	if err := validateVethPairContract(
		left,
		right,
		"wma012345670",
		"wmr01234567a",
	); err != nil {
		t.Fatalf("valid veth pair contract was rejected: %v", err)
	}

	tests := []struct {
		name      string
		mutate    func(*clientFlags, *clientFlags)
		leftLink  string
		rightLink string
	}{
		{
			name: "same socket",
			mutate: func(left, right *clientFlags) {
				right.socket = left.socket
			},
			leftLink:  "wma012345670",
			rightLink: "wmr01234567a",
		},
		{
			name: "same pid",
			mutate: func(left, right *clientFlags) {
				right.expectedAnchorPID = left.expectedAnchorPID
			},
			leftLink:  "wma012345670",
			rightLink: "wmr01234567a",
		},
		{
			name: "same namespace identity",
			mutate: func(left, right *clientFlags) {
				right.expectedDevice = left.expectedDevice
				right.expectedInode = left.expectedInode
			},
			leftLink:  "wma012345670",
			rightLink: "wmr01234567a",
		},
		{
			name: "different run",
			mutate: func(_ *clientFlags, right *clientFlags) {
				right.runID = "89abcdef"
			},
			leftLink:  "wma012345670",
			rightLink: "wmr01234567a",
		},
		{
			name: "wrong right role",
			mutate: func(_ *clientFlags, right *clientFlags) {
				right.role = "b"
			},
			leftLink:  "wma012345670",
			rightLink: "wmr01234567a",
		},
		{
			name:      "wrong left name",
			mutate:    func(_, _ *clientFlags) {},
			leftLink:  "foreign0",
			rightLink: "wmr01234567a",
		},
		{
			name:      "wrong right name",
			mutate:    func(_, _ *clientFlags) {},
			leftLink:  "wma012345670",
			rightLink: "foreign1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changedLeft := left
			changedRight := right
			test.mutate(&changedLeft, &changedRight)
			if err := validateVethPairContract(
				changedLeft,
				changedRight,
				test.leftLink,
				test.rightLink,
			); err == nil {
				t.Fatal("unsafe veth pair contract was accepted")
			}
		})
	}
}

func TestCreateVethPairUsesOneAtomicDualNamespaceLinkAdd(t *testing.T) {
	calls := 0
	err := createVethPair(
		"wma012345670",
		"wmr01234567a",
		41,
		42,
		func(link netlink.Link) error {
			calls++
			veth, ok := link.(*netlink.Veth)
			if !ok {
				t.Fatalf("link type = %T, want *netlink.Veth", link)
			}
			if veth.Name != "wma012345670" ||
				veth.PeerName != "wmr01234567a" {
				t.Fatalf("unexpected veth names: %+v", veth)
			}
			leftFD, leftOK := veth.Namespace.(netlink.NsFd)
			rightFD, rightOK := veth.PeerNamespace.(netlink.NsFd)
			if !leftOK || !rightOK || leftFD != 41 || rightFD != 42 {
				t.Fatalf(
					"veth namespace FDs = %T(%v), %T(%v), want NsFd(41), NsFd(42)",
					veth.Namespace,
					veth.Namespace,
					veth.PeerNamespace,
					veth.PeerNamespace,
				)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("create atomic veth pair: %v", err)
	}
	if calls != 1 {
		t.Fatalf("link add calls = %d, want exactly one", calls)
	}

	calls = 0
	err = createVethPair(
		"wma012345670",
		"wmr01234567a",
		41,
		41,
		func(netlink.Link) error {
			calls++
			return errors.New("must not be called")
		},
	)
	if err == nil {
		t.Fatal("same namespace FD was accepted")
	}
	if calls != 0 {
		t.Fatalf("invalid descriptor contract invoked link add %d times", calls)
	}
}
