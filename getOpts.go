package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"

	flags "github.com/jessevdk/go-flags"

	"github.com/yoshi389111/git-caesar/caesar/common"
)

type VersionType string

var caesarJsonVersions = []VersionType{
	VersionType(common.Version1),
	VersionType(common.Version2),
	VersionType(common.Version3),
}

func IsValidCaesarJsonVersion(v string) bool {
	for _, allowed := range caesarJsonVersions {
		if v == string(allowed) {
			return true
		}
	}
	return false
}

func (v *VersionType) UnmarshalFlag(value string) error {
	if IsValidCaesarJsonVersion(value) {
		*v = VersionType(value)
		return nil
	}
	return fmt.Errorf("invalid format version: %s, allowed versions are: %v", value, caesarJsonVersions)
}

// ref. https://pkg.go.dev/github.com/jessevdk/go-flags
type Options struct {
	Help          bool        `short:"h" long:"help" description:"print help and exit."`
	Version       bool        `short:"v" long:"version" description:"print version and exit."`
	VersionAll    bool        `short:"V" long:"version-all" hidden:"yes"`
	PublicKey     string      `short:"u" long:"public" value-name:"<target>" description:"github account, url or file."`
	PrivateKey    string      `short:"k" long:"private" value-name:"<id_file>" description:"ssh private key file."`
	InputPath     string      `short:"i" long:"input" value-name:"<input_file>" description:"the path of the file to read. default: stdin"`
	OutputPath    string      `short:"o" long:"output" value-name:"<output_file>" description:"the path of the file to write. default: stdout"`
	Decrypt       bool        `short:"d" long:"decrypt" description:"decryption mode."`
	FormatVersion VersionType `short:"F" long:"format-version" value-name:"<version>" description:"format version of the encrypted file." default:"1"`
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
