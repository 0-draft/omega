package main

import (
	"fmt"
	"os"

	"github.com/0-draft/omega/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "omega:", err)
		os.Exit(1)
	}
}
