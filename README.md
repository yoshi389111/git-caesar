# git-caesar

This command encrypts and decrypts files using the public key registered on GitHub and your own private key.

## usage

Usage:

```
  git-caesar [options]
```

Application Options:

```
  -h, --help                    print help and exit.
  -v, --version                 print version and exit.
  -u, --public=<target>         github account, url or file.
  -k, --private=<id_file>       ssh private file.
  -i, --input=<input_file>      the path of the file to read. default: stdin
  -o, --output=<output_file>    the path of the file to write. default: stdout
  -d, --decrypt                 decryption mode.
```

## Supported algorithms

The following algorithms are supported.

* rsa -- Key length is 1024 bits or more
* ecdsa -- secp256r1, secp384r1, secp521r1
* ed25519

The following algorithms are **not supported**.

* dsa
* rsa -- Key length is less than 1024 bits
* ecdsa-sk
* ed25519-sk

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
git-caesar -u https://gitlab.com/tanuki.keys -i secret.zip -o secret.txt
```

Same situation, no signature verification.

```
git-caesar -i secret.zip -o secret.txt
```

## Copyright and License

(C) 2023 SATO, Yoshiyuki

This software is released under the MIT License.
