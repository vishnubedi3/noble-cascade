package main

import (
	"fmt"
	"os"
	"strings"
)

// Safety Policy Guardrails (TheArchitectit Agent Guardrails Template)
// Hard-blocks destructive commands before execution.

var forbiddenCommands = []string{
	"rm -rf /",
	"drop database",
	"terraform destroy",
	"mkfs",
	"dd if=/dev/zero",
	"git push --force origin main",
}

func ValidateCommand(cmd string) bool {
	lower := strings.ToLower(cmd)
	for _, forbidden := range forbiddenCommands {
		if strings.Contains(lower, forbidden) {
			fmt.Printf("[!] HARD BLOCK: Destructive command detected ('%s'). Policy violation.\n", forbidden)
			return false
		}
	}
	fmt.Printf("[+] Safety guardrails passed for command: %s\n", cmd)
	return true
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: guardrails '<command>'")
		os.Exit(1)
	}
	cmd := os.Args[1]
	if !ValidateCommand(cmd) {
		os.Exit(1)
	}
	os.Exit(0)
}
