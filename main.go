package main

import (
	"fmt"
	"os"

	"github.com/aether-0/httpsuite/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
