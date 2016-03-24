package main

import (
	"os"

	"github.com/codegangsta/cli"
	"github.com/plumbing/modules/ssh"
)

func main() {
	app := cli.NewApp()

	app.Commands = []cli.Command{
		ssh.CmdWeb,
	}

	app.Flags = append(app.Flags, []cli.Flag{}...)
	app.Run(os.Args)
}
