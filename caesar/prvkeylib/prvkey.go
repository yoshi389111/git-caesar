package prvkeylib

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/yoshi389111/git-caesar/caesar"
	ec "github.com/yoshi389111/git-caesar/caesar/ecdsa"
	ed "github.com/yoshi389111/git-caesar/caesar/ed25519"
	rs "github.com/yoshi389111/git-caesar/caesar/rsa"
	"github.com/yoshi389111/git-caesar/iolib"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// Get the private key from the specified file path.
// If the file path is an empty string, search and get the default private key.
// If a passphrase is set for the private key, have the passphrase entered from the terminal.
func GetPrvKey(filePath string) (caesar.PrivateKey, error) {
	prvKeyBytes, err := ReadPrvKey(filePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load private key file.\n\t%w", err)
	}
	prvKey, err := ParsePrvKey(prvKeyBytes)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			pass := readPassphrase()
			if pass == "" {
				return nil, errors.New("No passphrase entered.")
			}
			prvKey, err = ParsePrvKeyWithPass(prvKeyBytes, pass)
		}
		return nil, fmt.Errorf("Failed to parse private key.\n\t%w", err)
	}
	return prvKey, nil
}

func readPassphrase() string {
	if !terminal.IsTerminal(int(os.Stdin.Fd())) {
		return ""
	}
	fmt.Fprint(os.Stderr, "Enter passphrase: ")
	bytePassword, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr, "")
	return string(bytePassword)
}

func ReadPrvKey(filePath string) ([]byte, error) {
	if filePath == "" {
		return SearchPrvKey()
	} else {
		return iolib.ReadFile(filePath)
	}
}

func SearchPrvKey() ([]byte, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("Failed to get home directory.\n\t%w", err)
	}
	sshDir := filepath.Join(usr.HomeDir, ".ssh")
	if !iolib.ExistsFile(sshDir) {
		return nil, fmt.Errorf("`%s` does not exist.\n\t%w", sshDir, err)
	}

	// search order (ref. man ssh)
	//
	// 1. `~/.ssh/id_dsa` -- Not applicable
	// 2. `~/.ssh/id_ecdsa`
	// 3. `~/.ssh/id_ecdsa_sk` -- Not applicable
	// 4. `~/.ssh/id_ed25519`
	// 5. `~/.ssh/id_ed25519_sk` -- Not applicable
	// 6. `~/.ssh/id_rsa`

	for _, fileName := range []string{"id_ecdsa", "id_ed25519", "id_rsa"} {
		filePath := filepath.Join(sshDir, fileName)
		if iolib.ExistsFile(filePath) {
			return iolib.ReadFile(filePath)
		}
	}
	return nil, errors.New("Default private keys could not be found.")
}

func ParsePrvKey(bytes []byte) (caesar.PrivateKey, error) {
	key, err := ssh.ParseRawPrivateKey(bytes)
	if err != nil {
		// Note: In case of `ssh.PassphraseMissingError`, it should be returned as is
		return nil, err // don't wrap
	}
	return toCaesarPrivateKey(key)
}

func ParsePrvKeyWithPass(bytes []byte, passphrase string) (caesar.PrivateKey, error) {
	key, err := ssh.ParseRawPrivateKeyWithPassphrase(bytes, []byte(passphrase))
	if err != nil {
		return nil, err // don't wrap
	}
	return toCaesarPrivateKey(key)
}

func toCaesarPrivateKey(key interface{}) (caesar.PrivateKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		prvKey := key.(*rsa.PrivateKey)
		return rs.NewPrivateKey(*prvKey), nil
	case *ecdsa.PrivateKey:
		prvKey := key.(*ecdsa.PrivateKey)
		return ec.NewPrivateKey(*prvKey), nil
	case *ed25519.PrivateKey:
		prvKey := key.(*ed25519.PrivateKey)
		return ed.NewPrivateKey(*prvKey), nil
	default:
		return nil, fmt.Errorf("`%T` type is not supported.", k)
	}
}
