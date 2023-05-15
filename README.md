# git-caesar

This command encrypts and decrypts files using the public key registered on GitHub and your own private key.

## Installation

```
go install github.com/yoshi389111/git-caesar@latest
```

Requires go 1.20 or higher

See below for how to uninstall

```
go clean -i github.com/yoshi389111/git-caesar
```

## Usage

Usage:

```
  git-caesar [options]
```

Application Options:

```
  -h, --help                    print help and exit.
  -v, --version                 print version and exit.
  -u, --public=<target>         github account, url or file.
  -k, --private=<id_file>       ssh private key file.
  -i, --input=<input_file>      the path of the file to read. default: stdin
  -o, --output=<output_file>    the path of the file to write. default: stdout
  -d, --decrypt                 decryption mode.
```

## Supported algorithms

List of supported public key prefixes:

* `ssh-rsa` -- Key length is 1024 bits or more
* `ecdsa-sha2-nistp256`
* `ecdsa-sha2-nistp384`
* `ecdsa-sha2-nistp521`
* `ssh-ed25519`

**Unsupported** public key prefix list:

* `ssh-dss`
* `ssh-rsa` -- Key length is less than 1024 bits
* `sk-ecdsa-sha2-nistp256@openssh.com`
* `sk-ssh-ed25519@openssh.com`

## Example of use

Encrypt your file `secret.txt` for GitHub user `octacat` and save it as `sceret.zip`.

```
git-caesar -u octacat -i secret.txt -o secret.zip
```

In the same situation, the private key uses `~/.ssh/id_secret`.

```
git-caesar -u octacat -i secret.txt -o secret.zip -k ~/.ssh/id_secret
```

Decrypt GitLab user `tanuki`'s file `secret.zip` and save it as `sceret.txt`.

```
git-caesar -d -u https://gitlab.com/tanuki.keys -i secret.zip -o secret.txt
```

Same situation, no signature verification.

```
git-caesar -d -i secret.zip -o secret.txt
```

## Related Tech Blog Articles

* dev.to [Passwordless encryption with public key for GitHub](https://dev.to/yoshi389111/passwordless-encryption-with-public-key-for-github-kb6) English
* Qiita [GitHub 用の公開鍵でパスワードレスの暗号化/復号をしてみる
](https://qiita.com/yoshi389111/items/238908e1933a8a4018c6) Japanese

## Copyright and License

(C) 2023 SATO, Yoshiyuki

This software is released under the MIT License.
