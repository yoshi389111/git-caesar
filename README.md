# git-caesar

This command encrypts and decrypts files using the public key registered on GitHub and your own private key.

## Installation

### How to build with GO command

Requires go 1.23.0 or higher

See below for how to install/upgrade.

```shell
go install github.com/yoshi389111/git-caesar@latest
```

See below for how to uninstall.

```shell
go clean -i github.com/yoshi389111/git-caesar
```

### How to install using Homebrew

See below for how to install/upgrade.

```shell
brew install yoshi389111/apps/git-caesar
```

See below for how to uninstall.

```shell
brew uninstall yoshi389111/apps/git-caesar
```

### Download from GitHub

Download the file that matches your operating environment from "Releases."

## Usage

```txt
Usage:

  git-caesar [options]

Application Options:

  -h, --help                        print help and exit.
  -v, --version                     print version and exit.
  -u, --public=<target>             github account, url or file.
  -k, --private=<id_file>           ssh private key file.
  -i, --input=<input_file>          the path of the file to read. default: stdin
  -o, --output=<output_file>        the path of the file to write. default: stdout
  -d, --decrypt                     decryption mode.
  -F, --format-version=<version>    format version of the encrypted file. (default: 1)
```

* `-u` specifies the location of the peer's public key. Get from `https://github.com/USER_NAME.keys` if the one specified looks like a GitHub username. If it starts with `http:` or `https:`, it will be fetched from the web. Otherwise, it will be determined as a file path. If you specify a file that looks like GitHub username, specify it with a path (e.g. `-u ./octacat`). Required for encryption. For decryption, perform signature verification if specified.
* `-k` Specify your private key. If not specified, it searches `~/.ssh/id_ecdsa`, `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` in order and uses the first one found.
* `-i` Input file. Plaintext file to be encrypted when encrypting. When decrypting, please specify the ciphertext file to be decrypted. If no options are specified, it reads from standard input.
* `-o` output file. Outputs to standard output if no option is specified.
* Specify `-d` for decrypt mode. Encrypted mode if not specified.
* `-F` specifies the file version of the cipher file. Currently, only version 1 is valid.

## Supported algorithms

List of supported public key prefixes:

* `ssh-rsa` -- Key length is 1024 bits or more
* `ecdsa-sha2-nistp256`
* `ecdsa-sha2-nistp384`
* `ecdsa-sha2-nistp521`
* `ssh-ed25519`

**Unsupported** public key prefix list:

* `ssh-dss` -- DSA
* `ssh-rsa` -- Key length is less than 1024 bits
* `sk-ecdsa-sha2-nistp256@openssh.com`
* `sk-ssh-ed25519@openssh.com`

## Example of use

Encrypt your file `secret.txt` for GitHub user `octacat` and save it as `secret.zip`.

```shell
git-caesar -u octacat -i secret.txt -o secret.zip
```

In the same situation, the private key uses `~/.ssh/id_secret`.

```shell
git-caesar -u octacat -i secret.txt -o secret.zip -k ~/.ssh/id_secret
```

Decrypt GitLab user `tanuki`'s file `secret.zip` and save it as `secret.txt`.

```shell
git-caesar -d -u https://gitlab.com/tanuki.keys -i secret.zip -o secret.txt
```

Same situation, no signature verification.

```shell
git-caesar -d -i secret.zip -o secret.txt
```

## Related Tech Blog Articles

* dev.to [Passwordless encryption with public key for GitHub](https://dev.to/yoshi389111/passwordless-encryption-with-public-key-for-github-kb6) English
* Qiita [GitHub 用の公開鍵でパスワードレスの暗号化/復号をしてみる](https://qiita.com/yoshi389111/items/238908e1933a8a4018c6) Japanese

## Copyright and License

&copy; 2023 SATO, Yoshiyuki

This software is released under the MIT License.
