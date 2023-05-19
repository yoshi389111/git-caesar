package main

import (
	"fmt"
	"os"

	"github.com/yoshi389111/git-caesar/caesar/prvkeylib"
	"github.com/yoshi389111/git-caesar/caesar/pubkeylib"
	"github.com/yoshi389111/git-caesar/iolib"
)

func main() {
	opts := getOpts()

	peerPubKeys, err := pubkeylib.GetPubKeys(opts.PublicKey)
	if err != nil {
		panic(err)
	}

	prvKey, err := prvkeylib.GetPrvKey(opts.PrivateKey)
	if err != nil {
		panic(err)
	}

	inBytes, err := iolib.ReadInputFile(opts.InputPath)
	if err != nil {
		panic(err)
	}

	var outBytes []byte
	if opts.Decrypt {
		outBytes, err = decrypt(peerPubKeys, prvKey, inBytes)
		if err != nil {
			panic(err)
		}

	} else {
		if peerPubKeys == nil {
			fmt.Fprintf(os.Stderr, "`-u` option missing\n")
			os.Exit(1)
		}
		if len(peerPubKeys) == 0 {
			fmt.Fprintf(os.Stderr, "Recipient's public key not found.\n")
			os.Exit(1)
		}
		outBytes, err = encrypt(peerPubKeys, prvKey, inBytes)
		if err != nil {
			panic(err)
		}
	}

	err = iolib.WriteOutputFile(opts.OutputPath, outBytes)
	if err != nil {
		panic(err)
	}
}
