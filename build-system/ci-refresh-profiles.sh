#!/usr/bin/env bash
# Rewrite the checked-in example provisioning profiles with a far-future
# ExpirationDate. rules_apple parses `.mobileprovision` with
# `openssl smime -verify -noverify` (signature intentionally NOT verified),
# so wrapping our patched plist with a fresh self-signed CMS envelope is
# enough to pass every downstream check (application-identifier /
# TeamIdentifier / aps-environment / ExpirationDate).
set -euo pipefail

SRC_DIR="build-system/example-configuration/provisioning"
DST_DIR="build-system/example-configuration/profiles"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$DST_DIR"

# Fresh self-signed cert used only to wrap the patched plist in a valid CMS.
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
  -sha256 -days 3650 -nodes -subj "/CN=larpgram-ci-fake" >/dev/null 2>&1

FUTURE_ISO="2035-12-31T23:59:59Z"
NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for src in "$SRC_DIR"/*.mobileprovision; do
  name="$(basename "$src")"
  # 1. Extract the raw plist (signature not checked).
  openssl smime -inform der -verify -noverify -in "$src" -out "$WORK/$name.plist"
  # 2. Bump ExpirationDate (and CreationDate) to fresh values. Both are XML
  #    <date>...</date> nodes right under the corresponding <key>.
  python3 - "$WORK/$name.plist" "$FUTURE_ISO" "$NOW_ISO" <<'PY'
import re, sys
path, exp, now = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()
def bump(key, value):
    # <key>Foo</key>\s*<date>...</date>
    pat = re.compile(r"(<key>" + re.escape(key) + r"</key>\s*<date>)[^<]*(</date>)")
    return pat.sub(r"\g<1>" + value + r"\g<2>", text, count=1)
text = bump("ExpirationDate", exp)
text = bump("CreationDate",   now)
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY
  # 3. Wrap back into DER-CMS. rules_apple reads with `openssl smime -verify -noverify`.
  openssl cms -sign -in "$WORK/$name.plist" -signer "$WORK/c.pem" -inkey "$WORK/k.pem" \
    -outform der -nodetach -out "$DST_DIR/$name" >/dev/null
  echo "refreshed $name (ExpirationDate=$FUTURE_ISO)"
done

echo "--- resulting profiles ---"
ls -la "$DST_DIR"
