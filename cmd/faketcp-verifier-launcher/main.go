package main

import (
	"fmt"
	"os"

	"github.com/syx0310/wg-mix-ebpf/internal/verifierlauncher"
)

func main() {
	if err := verifierlauncher.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: FakeTCP verifier launcher: %v\n", err)
		os.Exit(1)
	}
}
