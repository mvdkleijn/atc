package main

import (
	"fmt"
	"os"

	"github.com/concourse/atc/atccmd"
	"github.com/concourse/atc/auth/provider"
	"github.com/jessevdk/go-flags"
)

func main() {
	cmd := &atccmd.ATCCommand{}

	parser := flags.NewParser(cmd, flags.Default)
	parser.NamespaceDelimiter = "-"

	for _, p := range provider.GetProviders() {
		// AddAuthGroup will return a AuthConfig map which will somehow be passed to the validate (command.validate) and configuring
		// of authentication for default team (command.configureAuthForDefaultTeam)

		p.AddAuthGroup(parser)
	}

	args, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}

	err = cmd.Execute(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
