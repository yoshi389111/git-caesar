package pubkeylib

import (
	"regexp"
	"strings"
)

func IsGithubAccount(str string) bool {
	// GitHub account name validation in current
	//
	// + 1 to 39 characters
	// + Consists only of alphanumeric characters and hyphens
	// + does not start with a hyphen
	// + does not end with a hyphen
	// + no consecutive hyphens
	//
	// no existence check
	// no reserved word check (`help`, `about`, `pricing`, etc)

	if strings.Contains(str, "--") {
		return false
	}
	re := regexp.MustCompile(`^[a-zA-Z\d]([a-zA-Z\d-]{0,37}[a-zA-Z\d])?$`)
	return re.MatchString(str)
}
