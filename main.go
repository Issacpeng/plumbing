package main

import (
	"os"

	"github.com/codegangsta/cli"

	"github.com/containerops/plumbing/cmd"
	"github.com/containerops/plumbing/setting"
)

func main() {
	app := cli.NewApp()

	app.Name = setting.AppName
	app.Usage = setting.Usage
	app.Version = setting.Version
	app.Author = setting.Author
	app.Email = setting.Email

	app.Commands = []cli.Command{
		cmd.CmdHTTPS,
		cmd.CmdImport,
	}

	app.Flags = append(app.Flags, []cli.Flag{}...)
	app.Run(os.Args)
}
