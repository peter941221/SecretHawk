package main

import (
	"fmt"
	"os"

	"github.com/peter941221/secrethawk/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
