package main

import "runtime/debug"

// Embed version info at build time.
// e.g. `go build -ldflags "-X main.version=1.0.0"`
var version = ""

func getVersion() string {
	if version != "" {
		return version
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		return info.Main.Version
	}
	return "(version unknown)"
}
