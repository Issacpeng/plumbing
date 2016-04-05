package cmd

import (
	"github.com/codegangsta/cli"
)

var CmdImport = cli.Command{
	Name:        "import",
	Usage:       "import git repositories to plumbing system",
	Description: "import one or more bare repositories to the plumbing system.",
	Action:      runImport,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "path",
			Value: "",
			Usage: "repositories path or top level path",
		},
	},
}

func runImport(c *cli.Context) {

}
