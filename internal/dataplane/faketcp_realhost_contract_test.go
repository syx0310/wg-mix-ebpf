package dataplane

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	fakeTCPRealHostGateEnv           = "WG_MIX_FAKETCP_RUN_REALHOST_INTEGRATION"
	fakeTCPRealHostObjectEnv         = "WG_MIX_FAKETCP_REALHOST_OBJECT"
	fakeTCPRealHostBaselineObjectEnv = "WG_MIX_FAKETCP_REALHOST_BASELINE_OBJECT"
	fakeTCPRealHostIfindexEnv        = "WG_MIX_FAKETCP_REALHOST_IFINDEX"
	fakeTCPRealHostPeerIfindexEnv    = "WG_MIX_FAKETCP_REALHOST_PEER_IFINDEX"
	fakeTCPRealHostXDPModeEnv        = "WG_MIX_FAKETCP_REALHOST_XDP_MODE"
	fakeTCPRealHostRunIDEnv          = "WG_MIX_FAKETCP_REALHOST_RUN_ID"
	fakeTCPRealHostTempRootEnv       = "TMPDIR"
)

// fakeTCPRealHostContract is intentionally limited to values supplied by the
// reviewed v6 controller. The tests never discover an interface, object,
// bpffs path, or writable root by scanning the host.
type fakeTCPRealHostContract struct {
	experimentalObject string
	baselineObject     string
	ifindex            int
	peerIfindex        int
	xdpMode            fakeTCPRealHostXDPMode
	runID              string
	tempRoot           string
	vethName           string
	peerVethName       string
	vethAlias          string
	peerVethAlias      string
}

type fakeTCPRealHostXDPMode uint8

const fakeTCPRealHostXDPGeneric fakeTCPRealHostXDPMode = 1

type fakeTCPRealHostEnvLookup func(string) (string, bool)

func fakeTCPRealHostGateEnabled(lookup fakeTCPRealHostEnvLookup) (bool, error) {
	if lookup == nil {
		return false, fmt.Errorf("parse FakeTCP real-host gate: environment lookup is nil")
	}
	value, ok := lookup(fakeTCPRealHostGateEnv)
	if !ok || value == "" {
		return false, nil
	}
	if value != "1" {
		return false, fmt.Errorf("%s must be exactly 1 when set", fakeTCPRealHostGateEnv)
	}
	return true, nil
}

func parseFakeTCPRealHostContract(lookup fakeTCPRealHostEnvLookup) (fakeTCPRealHostContract, error) {
	if lookup == nil {
		return fakeTCPRealHostContract{}, fmt.Errorf("parse FakeTCP real-host contract: environment lookup is nil")
	}
	require := func(name string) (string, error) {
		value, ok := lookup(name)
		if !ok || value == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return "", fmt.Errorf("%s contains whitespace or control characters", name)
		}
		return value, nil
	}

	experimentalObject, err := require(fakeTCPRealHostObjectEnv)
	if err != nil {
		return fakeTCPRealHostContract{}, err
	}
	baselineObject, err := require(fakeTCPRealHostBaselineObjectEnv)
	if err != nil {
		return fakeTCPRealHostContract{}, err
	}
	if err := validateFakeTCPRealHostObjectPaths(experimentalObject, baselineObject); err != nil {
		return fakeTCPRealHostContract{}, err
	}

	ifindexText, err := require(fakeTCPRealHostIfindexEnv)
	if err != nil {
		return fakeTCPRealHostContract{}, err
	}
	ifindex, err := parseFakeTCPRealHostIfindex(fakeTCPRealHostIfindexEnv, ifindexText)
	if err != nil {
		return fakeTCPRealHostContract{}, err
	}
	peerIfindexText, err := require(fakeTCPRealHostPeerIfindexEnv)
	if err != nil {
		return fakeTCPRealHostContract{}, err
	}
	peerIfindex, err := parseFakeTCPRealHostIfindex(fakeTCPRealHostPeerIfindexEnv, peerIfindexText)
	if err != nil {
		return fakeTCPRealHostContract{}, err
	}
	if ifindex == peerIfindex {
		return fakeTCPRealHostContract{}, fmt.Errorf(
			"%s and %s must identify distinct veth endpoints",
			fakeTCPRealHostIfindexEnv,
			fakeTCPRealHostPeerIfindexEnv,
		)
	}

	xdpModeText, err := require(fakeTCPRealHostXDPModeEnv)
	if err != nil {
		return fakeTCPRealHostContract{}, err
	}
	if xdpModeText != "generic" {
		return fakeTCPRealHostContract{}, fmt.Errorf(
			"%s must be exactly generic, got %q",
			fakeTCPRealHostXDPModeEnv,
			xdpModeText,
		)
	}

	runID, err := require(fakeTCPRealHostRunIDEnv)
	if err != nil {
		return fakeTCPRealHostContract{}, err
	}
	if !validFakeTCPRealHostRunID(runID) {
		return fakeTCPRealHostContract{}, fmt.Errorf(
			"%s must be exactly eight lower-case nonzero hexadecimal characters",
			fakeTCPRealHostRunIDEnv,
		)
	}
	tempRoot, err := require(fakeTCPRealHostTempRootEnv)
	if err != nil {
		return fakeTCPRealHostContract{}, err
	}
	if err := validateFakeTCPRealHostTempRoot(tempRoot, runID); err != nil {
		return fakeTCPRealHostContract{}, err
	}

	prefix := "wg" + runID[:5]
	return fakeTCPRealHostContract{
		experimentalObject: experimentalObject,
		baselineObject:     baselineObject,
		ifindex:            ifindex,
		peerIfindex:        peerIfindex,
		xdpMode:            fakeTCPRealHostXDPGeneric,
		runID:              runID,
		tempRoot:           tempRoot,
		vethName:           prefix + "a",
		peerVethName:       prefix + "b",
		vethAlias:          "wg-mix-ebpf:" + runID + ":a",
		peerVethAlias:      "wg-mix-ebpf:" + runID + ":b",
	}, nil
}

func validateFakeTCPRealHostObjectPaths(experimentalObject, baselineObject string) error {
	for _, object := range []struct {
		name     string
		path     string
		basename string
	}{
		{fakeTCPRealHostObjectEnv, experimentalObject, "wg_mix_faketcp_experimental.o"},
		{fakeTCPRealHostBaselineObjectEnv, baselineObject, "wg_mix_tc.o"},
	} {
		if !filepath.IsAbs(object.path) || filepath.Clean(object.path) != object.path {
			return fmt.Errorf("%s must be a clean absolute path", object.name)
		}
		if filepath.Base(object.path) != object.basename {
			return fmt.Errorf("%s basename must be %s", object.name, object.basename)
		}
		if filepath.Base(filepath.Dir(object.path)) != "build" {
			return fmt.Errorf("%s must be an artifact directly below the reviewed build directory", object.name)
		}
	}
	if experimentalObject == baselineObject {
		return fmt.Errorf("FakeTCP experimental and baseline objects must be distinct")
	}
	if filepath.Dir(experimentalObject) != filepath.Dir(baselineObject) {
		return fmt.Errorf("FakeTCP experimental and baseline objects must share one reviewed build directory")
	}
	return nil
}

func parseFakeTCPRealHostIfindex(name, value string) (int, error) {
	if value == "" || value[0] == '0' {
		return 0, fmt.Errorf("%s must be a canonical positive decimal ifindex", name)
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("%s must be a canonical positive decimal ifindex", name)
	}
	if strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%s must use canonical decimal spelling", name)
	}
	return int(parsed), nil
}

func validFakeTCPRealHostRunID(runID string) bool {
	if len(runID) != 8 || runID == "00000000" {
		return false
	}
	for _, character := range runID {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validateFakeTCPRealHostTempRoot(tempRoot, runID string) error {
	if !filepath.IsAbs(tempRoot) || filepath.Clean(tempRoot) != tempRoot {
		return fmt.Errorf("%s must be a clean absolute path", fakeTCPRealHostTempRootEnv)
	}
	if filepath.Base(tempRoot) != "go-tmp-realhost" ||
		filepath.Base(filepath.Dir(tempRoot)) != runID {
		return fmt.Errorf(
			"%s must be the reviewed go-tmp-realhost directory directly below run %s",
			fakeTCPRealHostTempRootEnv,
			runID,
		)
	}
	return nil
}
