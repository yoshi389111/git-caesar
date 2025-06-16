#!/bin/sh
set -eu pipefail

WORKDIR=$(mktemp -d)

if [ ! -x target/git-caesar ]; then
    echo "git-caesar not found." >&2
    exit 1
fi

cp -p target/git-caesar "$WORKDIR"

(
    cd "$WORKDIR"

    # generate key pairs
    # for sender (Alice)
    ssh-keygen -t rsa -b 2048 -f alice_rsa_key -N '' -q
    ssh-keygen -t ecdsa -b 256 -f alice_ecdsa_key -N '' -q
    ssh-keygen -t ed25519 -f alice_ed25519_key -N '' -q

    # for receiver (Bob)
    ssh-keygen -t rsa -b 2048 -f bob_rsa_key -N '' -q
    ssh-keygen -t ecdsa -b 256 -f bob_ecdsa_key -N '' -q
    ssh-keygen -t ed25519 -f bob_ed25519_key -N '' -q

    cat bob_ecdsa_key.pub bob_ed25519_key.pub bob_rsa_key.pub > bob_pub_list.txt

    echo "Veni, vidi, vici." > plain.txt
    echo "Alea iacta est." >> plain.txt
    echo "Et tu, Brute?" >> plain.txt

    decrypt() {
        ./git-caesar -F 1 -d -k "bob_${2}_key" -u "alice_${1}_key.pub" -i "encrypted_${1}.bin" -o "decrypted_${1}_${2}.txt"
        if diff plain.txt "decrypted_${1}_${2}.txt"; then
            echo "Success. ${1} -> ${2}"
        else
            echo "Failed. ${1} -> ${2}"
        fi
        rm "decrypted_${1}_${2}.txt"
    }

    # encrypt (RSA)
    ./git-caesar -F 1 -k alice_rsa_key -u bob_pub_list.txt -i plain.txt -o encrypted_rsa.bin
    # decrypt
    decrypt rsa rsa
    decrypt rsa ecdsa
    decrypt rsa ed25519

    # encrypt (ECDSA)
    ./git-caesar -F 1 -k alice_ecdsa_key -u bob_pub_list.txt -i plain.txt -o encrypted_ecdsa.bin

    # decrypt
    decrypt ecdsa rsa
    decrypt ecdsa ecdsa
    decrypt ecdsa ed25519

    # encrypt (ED25519)
    ./git-caesar -F 1 -k alice_ed25519_key -u bob_pub_list.txt -i plain.txt -o encrypted_ed25519.bin

    # decrypt
    decrypt ed25519 rsa
    decrypt ed25519 ecdsa
    decrypt ed25519 ed25519
)

rm -rf "$WORKDIR"
