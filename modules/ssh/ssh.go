package ssh

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

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

var pubkeyContent = make(map[string]ssh.PublicKey)

func RunSshServer() error {
	config := &ssh.ServerConfig{
		/*		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				if c.User() == user && string(pass) == password {
					return nil, nil
				}
				return nil, fmt.Errorf("password rejected for %s", c.User())
			},*/
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			keydata := ssh.MarshalAuthorizedKey(key)
			fmt.Errorf("error reading SSH keydata: %v\r\n", keydata)
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

	raspath := fmt.Sprintf("%s/%s", setting.KeyPath, "id_rsa")

	if !utils.IsDirExist(setting.KeyPath) {
		os.MkdirAll(setting.KeyPath, os.ModePerm)
		err := exec.Command("ssh-keygen", "-f", raspath, "-t", "rsa", "-N", "").Run()
		if err != nil {
			panic(fmt.Sprintf("SSH: Fail to generate private key: %v\r\n", err))
		} else {
			fmt.Printf("SSH: New private key is generateed: %s\r\n", raspath)
		}
	}

	private, err := MakePrivateKeySignerFromFile(raspath)
	if err != nil {
		fmt.Errorf("[SSH] Load private file failed: %v", err.Error())
	}
	config.AddHostKey(private)
	/*
		privateKey, _, err := GenerateKey(2048)
		if err != nil {
			return err
		}
		privateBytes := EncodePrivateKey(privateKey)
		signer, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return err
		}
		config.AddHostKey(signer)
	*/

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
		fmt.Fprintf(os.Stderr, "[SSH] Wait: %v\r\n", err)
		return
	}
}

func LoadPublicKeysFromDir(keydir string) error {
	files, err := ioutil.ReadDir(keydir)
	if err != nil {
		fmt.Printf("[SSH] LoadPublicKeysFromDir: %v\r\n", err)
		return err
	}

	for _, file := range files {
		if strings.Contains(file.Name(), ".pub") {
			fullname := fmt.Sprintf("%s/%s", setting.KeyPath, file.Name())
			fmt.Printf("[SSH] LoadPublicKeysFromDir fullname: %v\r\n", fullname)
			pubkey, err := ParsePublicKeyFromFile(fullname)
			if err != nil {
				fmt.Errorf("[SSH] Parse public key from file failed: %v", err.Error())
				continue
			}
			fmt.Println("[SSH] LoadPublicKeysFromDir test2 \r\n")
			content := ssh.MarshalAuthorizedKey(pubkey)
			fmt.Printf("[SSH] LoadPublicKeysFromDir content: %v\r\n", content)
			fmt.Printf("[SSH] LoadPublicKeysFromDir pubkey: %v\r\n", pubkey)
			pubkeyContent[strings.TrimSpace(string(content))] = pubkey
		}
	}
	return nil
}

// SearchPublicKeyByContent searches content as prefix and returns public key found.
func SearchPublicKeyByContent(content string) (ssh.PublicKey, error) {
	key, has := pubkeyContent[content]
	if !has {
		return nil, fmt.Errorf("not find public key")
	}
	return key, nil
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

func ParsePublicKeyFromFile(keyFile string) (ssh.PublicKey, error) {
	fmt.Printf("[SSH] LoadPublicKeysFromDir keyFile: %v\r\n", keyFile)
	buffer, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("[SSH] error reading SSH key %s: '%v'", keyFile, err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(buffer)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func EncodePublicKeyContent(public *rsa.PublicKey) ([]byte, error) {
	fmt.Printf("[SSH] EncodePublicKeyContent public: %v\r\n", public)
	publicKey, err := ssh.NewPublicKey(public)
	if err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(publicKey), nil
}

func EncodePrivateKey(private *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(private),
		Type:  "RSA PRIVATE KEY",
	})
}

func EncodePublicKey(public *rsa.PublicKey) ([]byte, error) {
	publicBytes, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Bytes: publicBytes,
		Type:  "PUBLIC KEY",
	}), nil
}

func GenerateKey(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return private, &private.PublicKey, nil
}
