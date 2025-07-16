# GIT-CAESAR(1)

## NAME

**git-caesar** — Command-line tool for encrypting and decrypting files using public key cryptography

## SYNOPSIS

```shell
git-caesar [OPTIONS]
```

## DESCRIPTION

**git-caesar** is a command-line tool that encrypts and decrypts files using public keys registered on GitHub, GitLab, or local SSH key files.
Encryption uses the recipient's public key. Decryption uses your private key.

## OPTIONS

- `-h`, `--help`
  - Show help and exit.

- `-v`, `--version`
  - Show version and exit.

- `-u`, `--public=<target>`
  - Specify recipient's public key. Required for encryption.
    If a GitHub username is provided, the key is fetched from
    `https://github.com/USER_NAME.keys`.
    If the value starts with `http:` or `https:`, the key is fetched from the web.
    Otherwise, it is treated as a local file path.
    Used for signature verification in decryption.

- `-k`, `--private=<id_file>`
  - Specify your SSH private key file.
    If omitted, the tool searches `~/.ssh/id_ecdsa`, `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` in that order.

- `-i`, `--input=<input_file>`
  - Path to input file.
    For encryption, this is the plaintext file.
    For decryption, this is the encrypted file.
    Defaults to stdin.

- `-o`, `--output=<output_file>`
  - Path to output file.
    Defaults to stdout.

- `-d`, `--decrypt`
  - Decrypt mode. If not specified, encrypt mode is used.

- `-F`, `--format-version=<version>`
  - Format version of the encrypted file.
    Versions `1`, `2` and `3` are valid. Version `1` and `2` is deprecated.
    Default: `3`.

## EXAMPLES

- Encrypt `secret.txt` for GitHub user `octocat` and save as `secret.zip`:

    ```shell
    git-caesar -u octocat -i secret.txt -o secret.zip
    ```

- Encrypt using a specific private key (`~/.ssh/id_secret`):

    ```shell
    git-caesar -u octocat -i secret.txt -o secret.zip -k ~/.ssh/id_secret
    ```

- Decrypt a file for GitLab user `tanuki` and save it as `secret.txt`:

    ```shell
    git-caesar -d -u https://gitlab.com/tanuki.keys -i secret.zip -o secret.txt
    ```

- Decrypt a file without signature verification:

    ```shell
    git-caesar -d -i secret.zip -o secret.txt
    ```

## INSTALLATION

### How to build with GO command

Requires Go 1.24.0 or higher

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

## SUPPORTED ALGORITHMS

### Supported Public Key Algorithms

- `ssh-rsa` (key length 1024 bits or more)
- `ecdsa-sha2-nistp256`
- `ecdsa-sha2-nistp384`
- `ecdsa-sha2-nistp521`
- `ssh-ed25519`

**Unsupported:**

- `ssh-dss` (DSA)
- `ssh-rsa` (key length less than 1024 bits)
- `sk-ecdsa-sha2-nistp256@openssh.com`
- `sk-ssh-ed25519@openssh.com`

### Encryption and Signature Algorithms

#### Format version 3 (recommended)

- supported since v0.0.10

| Algorithm          | Encryption/Decryption                     | Signing/Verification         |
|--------------------|-------------------------------------------|------------------------------|
| AES                | AES-256-GCM                               | N/A                          |
| RSA (≤ 4096-bit)   | RSA-OAEP (SHA-256)                        | RSA-PSS (SHA-256)            |
| RSA (> 4096-bit)   | RSA-OAEP (SHA-256)                        | RSA-PSS (SHA-512)            |
| ECDSA/ECDH (P-256) | ECDH + HKDF-SHA-256 + AES-256-GCM         | ECDSA (SHA-256)              |
| ECDSA/ECDH (P-384) | ECDH + HKDF-SHA-256 + AES-256-GCM         | ECDSA (SHA-384)              |
| ECDSA/ECDH (P-521) | ECDH + HKDF-SHA-256 + AES-256-GCM         | ECDSA (SHA-512)              |
| ED25519/X25519     | X25519 + HKDF-SHA-256 + AES-256-GCM       | ED25519 (SHA-512)            |

<details>
<summary>Old format versions</summary>

#### Format version 2

- supported since v0.0.9
- deprecated since v0.0.10

| Algorithm        | Encryption/Decryption                       | Signing/Verification         |
|------------------|---------------------------------------------|------------------------------|
| AES              | AES-256-GCM                                 | N/A                          |
| RSA              | RSA-OAEP (SHA-256)                          | RSA-PSS (SHA-256)            |
| ECDSA/ECDH       | ECDH + HKDF-SHA-256 + AES-256-GCM           | ECDSA (SHA-256) ⚠️           |
| ED25519/X25519   | X25519 + HKDF-SHA-256 + AES-256-GCM         | ED25519 (SHA-512)            |

#### Format version 1

- supported since v0.0.1
- deprecated since v0.0.9

| Algorithm        | Encryption/Decryption                       | Signing/Verification         |
|------------------|---------------------------------------------|------------------------------|
| AES              | AES-256-CBC                                 | N/A                          |
| RSA              | RSA-OAEP (SHA-256)                          | RSA-PKCS1-v1_5 (SHA-256)     |
| ECDSA/ECDH       | ECDH + ⚠️SHA-256 (for key derivation) + AES-256-CBC   | ECDSA (SHA-256)   |
| ED25519/X25519   | X25519 + ⚠️SHA-256 (for key derivation) + AES-256-CBC | ED25519 (⚠️with pre-hashed SHA-256 input) |

</details>

## SECURITY

In this tool, the ECDSA and ED25519 signing public keys are reused for key exchange (ECDH / X25519).

- Using the signing public key for key exchange does not directly leak the recipient’s signing private key during the key exchange itself, because the private key is not transmitted or revealed in the protocol.
- The sender’s signing private key is also not leaked, as an ephemeral key for key exchange is used for each session on the sender’s side, and the sender's signing key is used only for signing.

However, this practice has the following potential security risks:

- If the signing private key is compromised, all past key exchanges using that key can be broken retroactively (forward secrecy is lost).
- Increased use of the signing private key raises the risk of side-channel attacks.

## SEE ALSO

- [Passwordless encryption with public key for GitHub (dev.to)](https://dev.to/yoshi389111/passwordless-encryption-with-public-key-for-github-kb6) — English article about this tool
- [GitHub 用の公開鍵でパスワードレスの暗号化/復号をしてみる (Qiita)](https://qiita.com/yoshi389111/items/238908e1933a8a4018c6) — Japanese article about this tool

## COPYRIGHT

&copy; 2023 SATO, Yoshiyuki. MIT Licensed.
