package pubkeylib

import (
	"testing"
)

func Test_IsGithubAccount(t *testing.T) {
	assertGithubAccount(t, "a", true)
	assertGithubAccount(t, "z", true)
	assertGithubAccount(t, "A", true)
	assertGithubAccount(t, "Z", true)
	assertGithubAccount(t, "0", true)
	assertGithubAccount(t, "9", true)
	assertGithubAccount(t, "fooBAR123", true)
	assertGithubAccount(t, "foo-BAR-123", true)

	assertGithubAccount(t, "", false)     // empty
	assertGithubAccount(t, "a a", false)  // space
	assertGithubAccount(t, "a_a", false)  // underscore
	assertGithubAccount(t, "a-", false)   // ending with a hyphen
	assertGithubAccount(t, "-a", false)   // leading with a hyphen
	assertGithubAccount(t, "a--a", false) // consecutive hyphens

	assertGithubAccount(t, "abcdefghijklm-NOPQRSTUVWXYZ-01234567890", true)   // 39
	assertGithubAccount(t, "abcdefghijklm-NOPQRSTUVWXYZ-0123456789-0", false) // 40
}

func assertGithubAccount(t *testing.T, name string, expect bool) {
	actual := IsGithubAccount(name)
	if expect != actual {
		t.Errorf("name: '%s', actual=%v, expect=%v", name, actual, expect)
	}
}
