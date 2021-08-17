#!/bin/bash

# (Re)generates the public/private Ed25519 keypairs of the verifier and the recovery.
# Best to run this script before building and using the verifier and recovery.
# You'll need the OpenSSL command line tool to do this.

# NOTE: You MUST run this in the root directory of the source code (ie. having directories pc/ and recovery/)!

# Verifier
lines=()
while IFS= read curline; do
	lines+=($curline)
done <<< $(openssl genpkey -text -algorithm ed25519)
verifier_privkey_unformatted="${lines[10]}${lines[11]}${lines[12]}" # Private key is at lines 10, 11, and 12.
verifier_pubkey_unformatted="${lines[14]}${lines[15]}${lines[16]}" # Public key is at lines 14, 15, and 16.
verifier_privkey="\x${verifier_privkey_unformatted//:/\\x}"
verifier_pubkey="\x${verifier_pubkey_unformatted//:/\\x}"

# Recovery
lines=()
while IFS= read curline; do
	lines+=($curline)
done <<< $(openssl genpkey -text -algorithm ed25519)
recovery_privkey_unformatted="${lines[10]}${lines[11]}${lines[12]}" # Private key is at lines 10, 11, and 12.
recovery_pubkey_unformatted="${lines[14]}${lines[15]}${lines[16]}" # Public key is at lines 14, 15, and 16.
recovery_privkey="\x${recovery_privkey_unformatted//:/\\x}"
recovery_pubkey="\x${recovery_pubkey_unformatted//:/\\x}"

nl='
'

# pubkey_verifier.h
printf '// AUTO-GENERATED - DO NOT MODIFY
#ifndef PUBKEY_VERIFIER
#define PUBKEY_VERIFIER

#define VERIFIER_ED25519_PUBKEY (unsigned char*)\"%s\"

#endif' "$verifier_pubkey" > pubkey_verifier.h
cp pubkey_verifier.h pc/
cp pubkey_verifier.h recovery/
rm pubkey_verifier.h

# privkey_verifier.h
printf '// AUTO-GENERATED - DO NOT MODIFY
#ifndef PRIVKEY_VERIFIER
#define PRIVKEY_VERIFIER

#define VERIFIER_ED25519_PRIVKEY (unsigned char*)\"%s\"

#endif' "$verifier_privkey" > privkey_verifier.h
cp privkey_verifier.h pc/
rm privkey_verifier.h

# pubkey_recovery.h
printf '// AUTO-GENERATED - DO NOT MODIFY
#ifndef PUBKEY_RECOVERY
#define PUBKEY_RECOVERY

#define RECOVERY_ED25519_PUBKEY (unsigned char*)\"%s\"

#endif' "$recovery_pubkey" > pubkey_recovery.h
cp pubkey_recovery.h pc/
cp pubkey_recovery.h recovery/
rm pubkey_recovery.h

# privkey_recovery.h
printf '// AUTO-GENERATED - DO NOT MODIFY
#ifndef PRIVKEY_RECOVERY
#define PRIVKEY_RECOVERY

#define RECOVERY_ED25519_PRIVKEY (unsigned char*)\"%s\"

#endif' "$recovery_privkey" > privkey_recovery.h
cp privkey_recovery.h recovery/
rm privkey_recovery.h
