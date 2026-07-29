package main

import (
	"fmt"
	"os"

	"github.com/syx0310/wg-mix-ebpf/internal/netnsanchor"
)

func main() {
	if err := netnsanchor.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "netns anchor: %v\n", err)
		os.Exit(1)
	}
}
