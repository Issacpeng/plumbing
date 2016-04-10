package ssh

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	_ "github.com/astaxie/beego/logs"
	"github.com/containerops/plumbing/setting"
	"github.com/containerops/plumbing/utils"
	"golang.org/x/crypto/ssh"
)

var sshkeyLoadLocker = sync.Mutex{}

const (
	MODE_READ  = 0
	MODE_WRITE = 1
)

var (
	validateCommands = map[string]int{
		"git-upload-pack":    MODE_READ,
		"git-upload-archive": MODE_READ,
		"git-receive-pack":   MODE_WRITE,
	}
)

var pubkeyContent map[string]*rsa.PublicKey

func RunSshServer(user, password string) {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %s", c.User())
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			keydata := ssh.MarshalAuthorizedKey(key)
			_, err := SearchPublicKeyByContent(strings.TrimSpace(string(keydata)))
			if err != nil {
				fmt.Sprintf("SearchPublicKeyByContent: %v\r\n", err)
				return nil, err
			}
			return &ssh.Permissions{Extensions: map[string]string{"key-id": string(0)}}, nil
		},
	}

	if !utils.IsDirExist(setting.RepoPath) {
		os.MkdirAll(setting.RepoPath, os.ModePerm)
	}

	if !utils.IsDirExist(setting.KeyPath) {
		os.MkdirAll(setting.KeyPath, os.ModePerm)
	}

	raspath := fmt.Sprintf("%s/%s", setting.KeyPath, "id_rsa")
	err := exec.Command("ssh-keygen", "-f", raspath, "-t", "rsa", "-N", "").Run()
	if err != nil {
		panic(fmt.Sprintf("SSH: Fail to generate private key: %v\r\n", err))
	} else {
		fmt.Printf("SSH: New private key is generateed: %s\r\n", raspath)
	}

	private, err := MakePrivateKeySignerFromFile(raspath)
	if err != nil {
		fmt.Errorf("[SSH] Load private file failed: %v", err.Error())
	}
	config.AddHostKey(private)

	if err := LoadPublicKeysFromDir(setting.KeyPath); err != nil {
		fmt.Errorf("[SSH] Load pubkey file failed: %v", err.Error())
	}

	listenaddress := fmt.Sprintf("%s:%s", setting.SshHost, setting.SshPort)
	listener, err := net.Listen("tcp", listenaddress)
	if err != nil {
		panic("[SSH] failed to listen for connection\r\n")
	}

	fmt.Printf("[SSH] service listen at port: %v\r\n", setting.SshPort)
	for {
		nConn, err := listener.Accept()
		if err != nil {
			fmt.Printf("[SSH] Error accepting incoming connection: %v\r\n", err)
			continue
		}
		go handleConn(nConn, config)
	}
}

func handleConn(conn net.Conn, config *ssh.ServerConfig) {
	fmt.Printf("[SSH] Handshaking for %s\r\n", conn.RemoteAddr())
	sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		if err == io.EOF {
			fmt.Printf("[SSH] Handshaking was terminated: %v\r\n", err)
		} else {
			fmt.Printf("[SSH] Error on handshaking: %v\r\n", err)
		}
		return
	}

	fmt.Printf("[SSH] Connection from %s (%s)\r\n", sConn.RemoteAddr(), sConn.ClientVersion())
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			fmt.Println("[SSH] could not accept channel.\r\n")
			return
		}

		go func(in <-chan *ssh.Request) {
			defer channel.Close()
			for req := range in {
				switch req.Type {
				case "exec":
					payload := string(req.Payload)
					i := strings.Index(payload, "git")
					if i == -1 {
						fmt.Sprintf("[SSH] %s is invalidate, only support git command!\r\n", payload)
						continue
					}
					cmd := payload[i:]
					handleGitcmd(cmd, req, channel)
					return
				}
			}
		}(requests)
	}
}

func handleGitcmd(cmd string, req *ssh.Request, channel ssh.Channel) {
	verb, args := parseGitcmd(cmd)
	_, has := validateCommands[verb]
	if !has {
		panic(fmt.Sprintf("[SSH] Unknown git command %s\r\n", verb))
		return
	}

	gitcmd := generateGitcmd(verb, args)
	gitcmd.Dir = setting.RepoPath

	gitcmdStart(gitcmd, req, channel)
	channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
}

func parseGitcmd(cmd string) (string, string) {
	cmdleft := strings.TrimLeft(cmd, "'()")
	cmdsplit := strings.SplitN(cmdleft, " ", 2)
	if len(cmdsplit) != 2 {
		return "", ""
	}
	return cmdsplit[0], strings.Replace(cmdsplit[1], "'/", "'", 1)
}

func generateGitcmd(verb string, args string) *exec.Cmd {
	repoPath := strings.ToLower(strings.Trim(args, "'"))
	verbs := strings.Split(verb, " ")

	var gitcmd *exec.Cmd
	if len(verbs) == 2 {
		gitcmd = exec.Command(verbs[0], verbs[1], repoPath)
	} else {
		gitcmd = exec.Command(verb, repoPath)
	}

	return gitcmd
}

func gitcmdStart(gitcmd *exec.Cmd, req *ssh.Request, channel ssh.Channel) {
	stdout, err := gitcmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[SSH] StdoutPipe: %v", err)
		return
	}
	stderr, err := gitcmd.StderrPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[SSH] StderrPipe: %v", err)
		return
	}
	input, err := gitcmd.StdinPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[SSH] StdinPipe: %v", err)
		return
	}

	if err = gitcmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "[SSH] Start: %v", err)
		return
	}

	req.Reply(true, nil)
	go io.Copy(input, channel)
	io.Copy(channel, stdout)
	io.Copy(channel.Stderr(), stderr)

	if err = gitcmd.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, "[SSH] Wait: %v", err)
		return
	}
}

func MakePrivateKeySignerFromFile(key string) (ssh.Signer, error) {
	// Create an actual signer.
	buffer, err := ioutil.ReadFile(key)
	if err != nil {
		return nil, fmt.Errorf("error reading SSH key %s: '%v'", key, err)
	}
	return MakePrivateKeySignerFromBytes(buffer)
}

func MakePrivateKeySignerFromBytes(buffer []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, fmt.Errorf("error parsing SSH key %s: '%v'", buffer, err)
	}
	return signer, nil
}

func ParsePublicKeyFromFile(keyFile string) (*rsa.PublicKey, error) {
	buffer, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("[SSH] error reading SSH key %s: '%v'", keyFile, err)
	}
	keyBlock, _ := pem.Decode(buffer)
	key, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[SSH] error parsing SSH key %s: '%v'", keyFile, err)
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("[SSH] SSH key could not be parsed as rsa public key")
	}
	return rsaKey, nil
}

func EncodePublicKey(public *rsa.PublicKey) ([]byte, error) {
	publicKey, err := ssh.NewPublicKey(public)
	if err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(publicKey), nil
}

func LoadPublicKeysFromDir(keypath string) error {
	files, err := ioutil.ReadDir(keypath)
	if err != nil {
		return err
	}

	for _, file := range files {
		filename := fmt.Sprintf("%s/%s", setting.KeyPath, file.Name())
		pubkey, err := ParsePublicKeyFromFile(filename)
		if err != nil {
			fmt.Errorf("[SSH] Parse public key from file failed: %v", err.Error())
			continue
		}
		content, err := EncodePublicKey(pubkey)
		if err != nil {
			fmt.Errorf("[SSH] Encode publicKey file failed: %v", err.Error())
			continue
		}

		pubkeyContent[string(content)] = pubkey
	}

	return nil
}

// SearchPublicKeyByContent searches content as prefix (leak e-mail part)
// and returns public key found.
func SearchPublicKeyByContent(content string) (*rsa.PublicKey, error) {
	key, has := pubkeyContent[content]
	if !has {
		return nil, fmt.Errorf("not find public key")
	}
	return key, nil
}
