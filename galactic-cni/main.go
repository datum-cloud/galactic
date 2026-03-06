package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/datum-cloud/galactic-cni/cni"
	"github.com/datum-cloud/galactic-cni/debug"
)

func main() {
	args := os.Args[1:]

	cmd := cni.NewCommand()

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version details",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(debug.Version())
		},
	}
	cmd.AddCommand(versionCmd)

	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		log.Fatalf("Execution failed: %v", err)
	}
}
