package setting

import (
	"fmt"

	"github.com/astaxie/beego/config"
)

var (
	conf          config.Configer
	AppName       string
	Usage         string
	Version       string
	Author        string
	Email         string
	RunMode       string
	ListenMode    string
	HttpsCertFile string
	HttpsKeyFile  string
	LogPath       string
	SshPort       string
	SshHost       string
	RepoPath      string
	KeyPath       string
	StartSsh      string
)

func init() {
	var err error

	conf, err = config.NewConfig("ini", "conf/containerops.conf")
	if err != nil {
		fmt.Errorf("Read conf/server.conf Error: %v", err)
	}

	if appname := conf.String("appname"); appname != "" {
		AppName = appname
	}

	if usage := conf.String("usage"); usage != "" {
		Usage = usage
	}

	if version := conf.String("version"); version != "" {
		Version = version
	}

	if author := conf.String("author"); author != "" {
		Author = author
	}

	if email := conf.String("email"); email != "" {
		Email = email
	}

	if runmode := conf.String("runmode"); runmode != "" {
		RunMode = runmode
	}

	if listenmode := conf.String("listenmode"); listenmode != "" {
		ListenMode = listenmode
	}

	if httpscertfile := conf.String("httpscertfile"); httpscertfile != "" {
		HttpsCertFile = httpscertfile
	}

	if httpskeyfile := conf.String("httpskeyfile"); httpskeyfile != "" {
		HttpsKeyFile = httpskeyfile
	}

	if logpath := conf.String("log::filepath"); logpath != "" {
		LogPath = logpath
	}

	if sshport := conf.String("plumbing::sshport"); sshport != "" {
		SshPort = sshport
	} else if sshport == "" {
		err = fmt.Errorf("ssh port config value is null")
	}

	if sshhost := conf.String("plumbing::sshhost"); sshhost != "" {
		SshHost = sshhost
	} else if sshhost == "" {
		err = fmt.Errorf("ssh host config value is null")
	}

	if repopath := conf.String("plumbing::repopath"); repopath != "" {
		RepoPath = repopath
	} else if repopath == "" {
		err = fmt.Errorf("repo path config value is null")
	}

	if keypath := conf.String("plumbing::keypath"); keypath != "" {
		KeyPath = keypath
	} else if keypath == "" {
		err = fmt.Errorf("key path config value is null")
	}

	if startssh := conf.String("plumbing::startssh"); startssh != "" {
		StartSsh = startssh
	} else if startssh == "" {
		err = fmt.Errorf("start ssh config value is null")
	}
}
