//go:build linux

package netnsanchor

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	selfImageTestMode     = "WG_MIX_EBPF_SELF_IMAGE_TEST_MODE"
	selfImageTestExpected = "WG_MIX_EBPF_SELF_IMAGE_TEST_EXPECTED"
)

func TestHeldSelfImageSurvivesExecutablePathReplacement(t *testing.T) {
	switch os.Getenv(selfImageTestMode) {
	case "launcher":
		runHeldSelfImageLauncher(t)
		return
	case "grandchild":
		runHeldSelfImageGrandchild(t)
		return
	}

	directory := t.TempDir()
	alias := filepath.Join(directory, "mutable-helper")
	copyExecutable(t, alias)
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\nexit 97\n"), 0700); err != nil {
		t.Fatalf("write replacement executable: %v", err)
	}

	command := exec.Command(
		alias,
		"-test.run=^TestHeldSelfImageSurvivesExecutablePathReplacement$",
	)
	command.Env = selfImageTestEnvironment("launcher", "")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("open launcher stdin: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open launcher stdout: %v", err)
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start mutable-path launcher: %v", err)
	}
	reader := bufio.NewReader(stdout)
	ready, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read launcher readiness: %v stderr=%s", err, stderr.String())
	}
	ready = strings.TrimSpace(ready)
	if !strings.HasPrefix(ready, "READY ") {
		t.Fatalf("unexpected launcher readiness %q stderr=%s", ready, stderr.String())
	}
	expected := strings.TrimPrefix(ready, "READY ")

	if err := os.Rename(replacement, alias); err != nil {
		t.Fatalf("replace launcher pathname: %v", err)
	}
	if _, err := io.WriteString(stdin, "continue\n"); err != nil {
		t.Fatalf("release launcher: %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatalf("close launcher stdin: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read rebound worker output: %v", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf(
			"held-image launcher failed after pathname replacement: %v stderr=%s output=%s",
			err,
			stderr.String(),
			output,
		)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] != "BOUND "+expected {
		t.Fatalf(
			"worker rebound to replacement path: ready=%q output=%q stderr=%s",
			ready,
			output,
			stderr.String(),
		)
	}
	// The launcher and grandchild are test binaries executed directly rather
	// than through `go test`. Go 1.26 prints one PASS line for each nested test
	// binary after the identity assertion succeeds. Treat those framework lines
	// as transport noise, but reject every other trailing line so the test still
	// fails closed on unexpected worker output.
	for _, line := range lines[1:] {
		if line != "PASS" {
			t.Fatalf(
				"held-image worker emitted unexpected output: ready=%q output=%q stderr=%s",
				ready,
				output,
				stderr.String(),
			)
		}
	}
}

func TestWorkerImageValidationFailsClosed(t *testing.T) {
	image, err := openSelfImage()
	if err != nil {
		t.Fatalf("hold current test image: %v", err)
	}
	defer image.close()
	if err := validateWorkerImage(int(image.file.Fd()), image.identity); err != nil {
		t.Fatalf("matching held image was rejected: %v", err)
	}
	changed := image.identity
	changed.Inode++
	if err := validateWorkerImage(int(image.file.Fd()), changed); err == nil {
		t.Fatal("changed expected image identity was accepted")
	}
	command := image.command([]string{"unused"})
	if command.Path != "/proc/self/fd/3" {
		t.Fatalf("worker command path = %q, want held FD path", command.Path)
	}
	if len(command.ExtraFiles) != 1 || command.ExtraFiles[0] != image.file {
		t.Fatal("worker command did not inherit the held self image as FD 3")
	}
}

func TestBootstrapImageFDIsValidatedAndConsumed(t *testing.T) {
	image, err := openSelfImage()
	if err != nil {
		t.Fatalf("hold current test image: %v", err)
	}
	defer image.close()
	descriptor, err := unix.Dup(int(image.file.Fd()))
	if err != nil {
		t.Fatalf("duplicate held image: %v", err)
	}
	if err := os.Setenv(bootstrapFDEnv, strconv.Itoa(descriptor)); err != nil {
		_ = unix.Close(descriptor)
		t.Fatalf("set bootstrap image FD: %v", err)
	}
	if err := consumeBootstrapImageFD(); err != nil {
		t.Fatalf("consume matching bootstrap image FD: %v", err)
	}
	if _, present := os.LookupEnv(bootstrapFDEnv); present {
		t.Fatal("bootstrap image FD environment was not removed")
	}
	if _, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0); err == nil {
		t.Fatal("bootstrap image FD remained open after validation")
	}

	harmless, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open mismatched bootstrap file: %v", err)
	}
	mismatchedFD, err := unix.Dup(int(harmless.Fd()))
	_ = harmless.Close()
	if err != nil {
		t.Fatalf("duplicate mismatched bootstrap file: %v", err)
	}
	if err := os.Setenv(bootstrapFDEnv, strconv.Itoa(mismatchedFD)); err != nil {
		_ = unix.Close(mismatchedFD)
		t.Fatalf("set mismatched bootstrap FD: %v", err)
	}
	if err := consumeBootstrapImageFD(); err == nil {
		t.Fatal("mismatched bootstrap image FD was accepted")
	}
}

func runHeldSelfImageLauncher(t *testing.T) {
	image, err := openSelfImage()
	if err != nil {
		t.Fatalf("hold launcher image: %v", err)
	}
	defer image.close()
	fmt.Printf("READY %d:%d\n", image.identity.Device, image.identity.Inode)
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatalf("wait for pathname replacement: %v", err)
	}
	command := image.command(
		[]string{
			"-test.run=^TestHeldSelfImageSurvivesExecutablePathReplacement$",
		},
	)
	command.Env = selfImageTestEnvironment(
		"grandchild",
		fmt.Sprintf(
			"%d:%d",
			image.identity.Device,
			image.identity.Inode,
		),
	)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		t.Fatalf("run worker from held self image: %v", err)
	}
}

func runHeldSelfImageGrandchild(t *testing.T) {
	expectedParts := strings.Split(os.Getenv(selfImageTestExpected), ":")
	if len(expectedParts) != 2 {
		t.Fatalf("invalid expected held-image identity")
	}
	expectedDevice, err := strconv.ParseUint(expectedParts[0], 10, 64)
	if err != nil {
		t.Fatalf("parse expected device: %v", err)
	}
	expectedInode, err := strconv.ParseUint(expectedParts[1], 10, 64)
	if err != nil {
		t.Fatalf("parse expected inode: %v", err)
	}
	descriptor, err := unix.Open("/proc/self/exe", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open rebound worker image: %v", err)
	}
	defer unix.Close(descriptor)
	var metadata unix.Stat_t
	if err := unix.Fstat(descriptor, &metadata); err != nil {
		t.Fatalf("stat rebound worker image: %v", err)
	}
	if uint64(metadata.Dev) != expectedDevice || metadata.Ino != expectedInode {
		t.Fatalf(
			"rebound worker image=%d:%d, want=%d:%d",
			metadata.Dev,
			metadata.Ino,
			expectedDevice,
			expectedInode,
		)
	}
	fmt.Printf("BOUND %d:%d\n", expectedDevice, expectedInode)
}

func copyExecutable(t *testing.T, destination string) {
	t.Helper()
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatalf("open current test executable: %v", err)
	}
	defer source.Close()
	target, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		t.Fatalf("create mutable executable alias: %v", err)
	}
	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		t.Fatalf("copy current test executable: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("close mutable executable alias: %v", err)
	}
}

func selfImageTestEnvironment(mode, expected string) []string {
	environment := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, selfImageTestMode+"=") ||
			strings.HasPrefix(entry, selfImageTestExpected+"=") {
			continue
		}
		environment = append(environment, entry)
	}
	environment = append(environment, selfImageTestMode+"="+mode)
	if expected != "" {
		environment = append(
			environment,
			selfImageTestExpected+"="+expected,
		)
	}
	return environment
}
