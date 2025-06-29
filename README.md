# git-caesar

This command encrypts and decrypts files using the public key registered on GitHub and your own private key.

In addition to keys registered on github, you can also specify keys registered on gitlab or SSH keys in local files.

## Installation

### How to build with GO command

Requires go 1.24.0 or higher

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
  -F, --format-version=<version>    format version of the encrypted file. (default: 2)
```

* `-u` specifies the location of the peer's public key. Get from `https://github.com/USER_NAME.keys` if the one specified looks like a GitHub username. If it starts with `http:` or `https:`, it will be fetched from the web. If you want to use a GitLab user's key for example, specify the full URL (e.g. `-u https://gitlab.com/USERNAME.keys`). Otherwise, it will be determined as a file path. If you specify a file that looks like GitHub username, specify it with a path (e.g. `-u ./octocat`). Required for encryption. For decryption, perform signature verification if specified.
* `-k` Specify your private key. If not specified, it searches `~/.ssh/id_ecdsa`, `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` in order and uses the first one found.
* `-i` Input file. Plaintext file to be encrypted when encrypting. When decrypting, please specify the ciphertext file to be decrypted. If no options are specified, it reads from standard input.
* `-o` output file. Outputs to standard output if no option is specified.
* Specify `-d` for decrypt mode. Encrypted mode if not specified.
* `-F` specifies the file version of the cipher file. Currently, versions `1` and `2` are valid. The default value is `1` for versions 0.0.9 and below, and `2` for versions 1.0.0 and above.  
  **Note:** Format version `1` is deprecated and should not be used for new files.

## Example of use

Encrypt your file `secret.txt` for GitHub user `octocat` and save it as `secret.zip`.

```shell
git-caesar -u octocat -i secret.txt -o secret.zip
```

In the same situation, the private key uses `~/.ssh/id_secret`.

```shell
git-caesar -u octocat -i secret.txt -o secret.zip -k ~/.ssh/id_secret
```

Decrypt GitLab user `tanuki`'s file `secret.zip` and save it as `secret.txt`.

```shell
git-caesar -d -u https://gitlab.com/tanuki.keys -i secret.zip -o secret.txt
```

Same situation, no signature verification.

```shell
git-caesar -d -i secret.zip -o secret.txt
```

## Supported Public Key Algorithms

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

## Algorithms used

### Format version 2 (since version 0.0.9)

| Algorithm | Encryption/Decryption | Signing/Verification |
|-----------|-----------------------|----------------------|
| AES       | AES-256-GCM           | N/A                  |
| RSA       | RSA-OAEP (SHA-256)    | RSA-PSS (SHA-256)    |
| ECDSA/ECDH | ECDH + HKDF-SHA-256 + AES-256-GCM | ECDSA (SHA-256) |
| ED25519/X25519 | X25519 + HKDF-SHA-256 + AES-256-GCM | ED25519 (SHA-512 internally) |

### Format version 1 (**deprecated** since version 1.0.0)

| Algorithm | Encryption/Decryption | Signing/Verification |
|-----------|-----------------------|----------------------|
| AES       | AES-256-CBC           | N/A                  |
| RSA       | RSA-OAEP (SHA-256)    | RSA-PKCS1-v1_5 (SHA-256) |
| ECDSA/ECDH | ECDH + ⚠️SHA-256 (for key derivation) + AES-256-CBC | ECDSA (SHA-256) |
| ED25519/X25519 | X25519 + ⚠️SHA-256 (for key derivation) + AES-256-CBC | ED25519 (⚠️with pre-hashed SHA-256 input) |

## Security Considerations

In this command, the ecdsa / ed25519 public key for signing is reused for key exchange (ecdh / x25519).

If you use this command to reuse a signing public key (such as ECDSA or Ed25519) as a key exchange public key (such as ECDH or X25519), there are some important security considerations. It’s not strictly forbidden in theory, but doing so carries these risks:

* Using the signing public key for key exchange does not directly leak the recipient’s signing private key during the key exchange itself, because the private key is not transmitted or revealed in the protocol.

* The sender’s own signing private key is also not leaked by this use, assuming ephemeral keys are used on the sender side for each session, and the sender’s signing key is only used for signatures.

* **However, if the recipient’s signing private key is ever compromised**, all past key exchanges using that key can be broken retroactively, since the same secret scalar was used for all the Diffie-Hellman calculations. This means forward secrecy is lost.

* Additionally, reusing the signing private key for key exchange calculations increases the number of operations using that key, which can expand the attack surface for side-channel attacks (e.g., timing or power analysis). More opportunities to observe operations can make extracting the private key easier in practice.

* Finally, using the same key for both authentication (signatures) and key agreement (encryption) breaks clear separation of roles. It complicates key management, increases the consequences of a single key leak, and can introduce unforeseen protocol interactions.

## Related Tech Blog Articles

* dev.to [Passwordless encryption with public key for GitHub](https://dev.to/yoshi389111/passwordless-encryption-with-public-key-for-github-kb6) English
* Qiita [GitHub 用の公開鍵でパスワードレスの暗号化/復号をしてみる](https://qiita.com/yoshi389111/items/238908e1933a8a4018c6) Japanese

## Copyright and License

&copy; 2023 SATO, Yoshiyuki

This software is released under the MIT License.
