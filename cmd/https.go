package cmd

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/codegangsta/cli"
	"gopkg.in/macaron.v1"

	"github.com/containerops/plumbing/modules/ssh"
	"github.com/containerops/plumbing/setting"
	"github.com/containerops/plumbing/utils"
	"github.com/containerops/plumbing/web"
)

var CmdHTTPS = cli.Command{
	Name:        "web",
	Usage:       "start plumbing web service",
	Description: "plumbing is a key/value engine for Git backend storage.",
	Action:      runHTTPS,
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "address",
			Value: "0.0.0.0",
			Usage: "web service listen ip, default is 0.0.0.0; if listen with Unix Socket, the value is sock file path.",
		},
		cli.IntFlag{
			Name:  "port",
			Value: 80,
			Usage: "web service listen at port 80; if run with https will be 443.",
		},
	},
}

func runHTTPS(c *cli.Context) {
	m := macaron.New()

	//Set Macaron Web Middleware And Routers
	web.SetPlumbingMacaron(m)

	//Start SSH Server if value is true
	if setting.StartSsh == "true" {
		ssh.RunSshServer()
		fmt.Printf("SSH server started on :%v", setting.SshPort)
	}

	switch setting.ListenMode {
	case "http":
		listenaddr := fmt.Sprintf("%s:%d", c.String("address"), c.Int("port"))
		if err := http.ListenAndServe(listenaddr, m); err != nil {
			fmt.Printf("Start Plumbing http service error: %v\n", err.Error())
		}
		break
	case "https":
		listenaddr := fmt.Sprintf("%s:443", c.String("address"))
		server := &http.Server{Addr: listenaddr, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS10}, Handler: m}
		if err := server.ListenAndServeTLS(setting.HttpsCertFile, setting.HttpsKeyFile); err != nil {
			fmt.Printf("Start Plumbing https service error: %v\n", err.Error())
		}
		break
	case "unix":
		listenaddr := fmt.Sprintf("%s", c.String("address"))
		if utils.IsFileExist(listenaddr) {
			os.Remove(listenaddr)
		}

		if listener, err := net.Listen("unix", listenaddr); err != nil {
			fmt.Printf("Start Plumbing unix socket error: %v\n", err.Error())
		} else {
			server := &http.Server{Handler: m}
			if err := server.Serve(listener); err != nil {
				fmt.Printf("Start Plumbing unix socket error: %v\n", err.Error())
			}
		}
		break
	default:
		break
	}
}
