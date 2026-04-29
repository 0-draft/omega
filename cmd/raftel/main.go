package main

import (
	"fmt"
	"os"

	"github.com/kanywst/raftel/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "raftel:", err)
		os.Exit(1)
	}
}
