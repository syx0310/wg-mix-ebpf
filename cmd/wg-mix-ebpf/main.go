package main

import (
	"context"
	"fmt"
	"os"

	"github.com/syx0310/wg-mix-ebpf/internal/app"
)

func main() {
	if err := app.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
