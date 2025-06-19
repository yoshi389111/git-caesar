#!/bin/sh
set -eu

WORKDIR=$(mktemp -d -t "git-caesar-roundtrip-XXXXXX" )
GIT_CAESAR=./target/git-caesar

if [ ! -x "$GIT_CAESAR" ]; then
    echo "${GIT_CAESAR} not found." >&2
    exit 1
fi

generate_keys() {
    ssh-keygen -t rsa -b 2048 -f "$WORKDIR/${1}_rsa_key" -N '' -q
    ssh-keygen -t ecdsa -b 256 -f "$WORKDIR/${1}_ecdsa_key" -N '' -q
    ssh-keygen -t ed25519 -f "$WORKDIR/${1}_ed25519_key" -N '' -q
}

# generate key pairs for sender (Alice)
generate_keys "alice"

# generate key pairs for receiver (Bob)
generate_keys "bob"

# create receiver's public key list
BOB_PUB_LIST="$WORKDIR/bob_pub_list.txt"
cat "$WORKDIR/bob_ecdsa_key.pub" \
    "$WORKDIR/bob_ed25519_key.pub" \
    "$WORKDIR/bob_rsa_key.pub" \
     > "$BOB_PUB_LIST"

# create message file
MESSAGE_FILE="$WORKDIR/plain.txt"
cat <<EOF > "$MESSAGE_FILE"
Veni, vidi, vici.
Alea iacta est.
Et tu, Brute?
EOF

HAS_ERROR=0

for VERSION in 1 2; do

    for ALICE_KEY_TYPE in rsa ecdsa ed25519; do

        ALICE_PUB_KEY="$WORKDIR/alice_${ALICE_KEY_TYPE}_key.pub"
        ALICE_PRV_KEY="$WORKDIR/alice_${ALICE_KEY_TYPE}_key"
        ENCRYPTED_FILE="$WORKDIR/encrypted_${ALICE_KEY_TYPE}_${VERSION}.bin"

        "$GIT_CAESAR" -F "$VERSION" \
            -k "$ALICE_PRV_KEY" \
            -u "$BOB_PUB_LIST" \
            -i "$MESSAGE_FILE" \
            -o "$ENCRYPTED_FILE"

        for BOB_KEY_TYPE in rsa ecdsa ed25519; do

            BOB_PRV_KEY="$WORKDIR/bob_${BOB_KEY_TYPE}_key"
            DECRYPTED_FILE="$WORKDIR/decrypted_${ALICE_KEY_TYPE}_${BOB_KEY_TYPE}_${VERSION}.txt"

            "$GIT_CAESAR" -d \
                -k "$BOB_PRV_KEY" \
                -u "$ALICE_PUB_KEY" \
                -i "$ENCRYPTED_FILE" \
                -o "$DECRYPTED_FILE"

            if cmp -s "$MESSAGE_FILE" "$DECRYPTED_FILE"; then
                echo "Success. ${ALICE_KEY_TYPE} -> ${BOB_KEY_TYPE} / Ver. ${VERSION}"
            else
                echo "Failed. ${ALICE_KEY_TYPE} -> ${BOB_KEY_TYPE} / Ver. ${VERSION}"
                HAS_ERROR=1
            fi
        done
    done
done

if [ "$HAS_ERROR" -ne 0 ]; then
    echo "Some tests failed." >&2
    echo "Please check the following folder: $WORKDIR"
    exit 1
else
    echo "All tests passed successfully."
    rm -rf "$WORKDIR"
fi
