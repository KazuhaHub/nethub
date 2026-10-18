package main

import (
	"fmt"
	"io"
	"os"
)

var version = "dev"

const usage = `Usage: nethub <command>

Commands:
  web          Run the console
  authz        Run device and relay authorization
  migrate      Apply database migrations
  init         Prepare deployment configuration and secrets
  doctor       Check deployment readiness
  admin        Manage the initial administrator
  version      Print the build version

Service and deployment commands are not implemented in this foundation build.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "version does not accept arguments")
			return 2
		}
		fmt.Fprintln(stdout, "nethub", version)
		return 0
	case "web", "authz", "migrate", "init", "doctor", "admin":
		fmt.Fprintf(stderr, "%s is not implemented in this foundation build\n", args[0])
		return 1
	default:
		fmt.Fprintln(stderr, "Unknown command. Run nethub help for available commands.")
		return 2
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
