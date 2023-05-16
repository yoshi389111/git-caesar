package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"

	flags "github.com/jessevdk/go-flags"
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
			fmt.Fprintf(os.Stderr, "git-caesar: `-u` option missing\n")
			os.Exit(1)
		}
		if len(peerPubKeys) == 0 {
			fmt.Fprintf(os.Stderr, "git-caesar: Recipient's public key not found.\n")
			os.Exit(1)
		}
		outBytes, err = encrypt(peerPubKeys, prvKey, inBytes)
		if err != nil {
			panic(err)
		}
	}

	err = iolib.WriteInputFile(opts.OutputPath, outBytes)
	if err != nil {
		panic(err)
	}
}

// Embed version info at build time.
// e.g. `go build -ldflags "-X main.version=1.0.0"`
var version = ""

func getVersion() string {
	if version != "" {
		return version
	}

	if info, ok := debug.ReadBuildInfo(); !ok {
		return info.Main.Version
	}
	return "(version unknown)"
}

// ref. https://pkg.go.dev/github.com/jessevdk/go-flags
type Options struct {
	Help       bool   `short:"h" long:"help" description:"print help and exit."`
	Version    bool   `short:"v" long:"version" description:"print version and exit."`
	VersionAll bool   `short:"V" long:"version-all" hidden:"yes"`
	PublicKey  string `short:"u" long:"public" value-name:"<target>" description:"github account, url or file."`
	PrivateKey string `short:"k" long:"private" value-name:"<id_file>" description:"ssh private key file."`
	InputPath  string `short:"i" long:"input" value-name:"<input_file>" description:"the path of the file to read. default: stdin"`
	OutputPath string `short:"o" long:"output" value-name:"<output_file>" description:"the path of the file to write. default: stdout"`
	Decrypt    bool   `short:"d" long:"decrypt" description:"decryption mode."`
}

func getOpts() Options {
	var opts Options
	parser := flags.NewParser(&opts, flags.PassDoubleDash)
	parser.Usage = "[options]"
	_, err := parser.Parse()
	if opts.Version {
		// e.g "git-caesar 1.0.0 Linux/amd64 (go1.20.4)"
		fmt.Printf("%s %s %s/%s (%s)\n",
			filepath.Base(os.Args[0]),
			getVersion(),
			runtime.GOOS,
			runtime.GOARCH,
			runtime.Version())
		os.Exit(0)
	}
	if opts.VersionAll {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			fmt.Println("build info not found.")
			os.Exit(1)
		}
		fmt.Printf("%s %s\n", info.Main.Path, info.Main.Version)
		for _, m := range info.Deps {
			fmt.Printf("%s %s\n", m.Path, m.Version)
		}
		os.Exit(0)
	}
	if opts.Help {
		parser.WriteHelp(os.Stderr)
		os.Exit(0)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return opts
}
