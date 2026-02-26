package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/peter941221/secrethawk/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		var exitErr *cli.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.Message != "" {
				fmt.Fprintf(os.Stderr, "error: %v\n", exitErr)
			}
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}
