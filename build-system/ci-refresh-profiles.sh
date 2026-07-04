#!/usr/bin/env bash
# Rewrite the checked-in example provisioning profiles so a macOS CI runner
# WITHOUT any Apple Developer account can still complete `bazel build`:
#
#   1. Generate one throwaway self-signed identity (cert + key) up front and
#      import it into the login keychain so `codesign` can find it.
#   2. For every checked-in profile:
#        * extract the plist body
#        * push ExpirationDate 10 years into the future
#        * inject entitlements the app declares but the 2022-era template
#          doesn't already have (applesignin, gpu, communication-notifications,
#          etc.). rules_apple only fails on MISSING profile keys, extras are ok.
#        * replace <key>DeveloperCertificates</key> with the DER of OUR self
#          signed cert, and rename the profile's Name so codesign resolves
#          the right identity via CN match.
#        * rewrap in fresh CMS.
#
# The resulting .ipa is signed with a bogus identity — perfectly fine as an
# input to AltStore / Sideloadly / any resigning tool.
set -euo pipefail

SRC_DIR="build-system/example-configuration/provisioning"
DST_DIR="build-system/example-configuration/profiles"
CRT_DIR="build-system/example-configuration/certs"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$DST_DIR" "$CRT_DIR"

# --- 1. one throwaway identity for every profile ----------------------------

CERT_CN="iPhone Distribution: larpgram CI (C67CF9S4VU)"
openssl req -x509 -newkey rsa:2048 \
  -keyout "$WORK/identity.key" \
  -out    "$WORK/identity.pem" \
  -sha256 -days 3650 -nodes \
  -subj "/CN=$CERT_CN/OU=C67CF9S4VU/O=larpgram/C=US" \
  -addext "extendedKeyUsage=codeSigning" >/dev/null 2>&1
# CMS envelope signer (also self-signed, separate to avoid mixing purposes).
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/cms.key" -out "$WORK/cms.pem" \
  -sha256 -days 3650 -nodes -subj "/CN=larpgram-ci-cms" >/dev/null 2>&1

# Base64 DER of the identity certificate for the DeveloperCertificates array.
openssl x509 -in "$WORK/identity.pem" -outform der -out "$WORK/identity.der"
CERT_B64=$(base64 -i "$WORK/identity.der" | tr -d '\n')

# Ship a .p12 next to the profiles so the "Install identity" step below can
# import it. Empty password.
openssl pkcs12 -export \
  -out "$CRT_DIR/identity.p12" \
  -inkey "$WORK/identity.key" \
  -in    "$WORK/identity.pem" \
  -password pass: >/dev/null 2>&1

# --- 2. rewrite every profile ----------------------------------------------

FUTURE_ISO="2035-12-31T23:59:59Z"
NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for src in "$SRC_DIR"/*.mobileprovision; do
  name="$(basename "$src")"
  # 2.1 extract the raw plist (signature not checked)
  openssl smime -inform der -verify -noverify -in "$src" -out "$WORK/$name.plist"

  # 2.2 python does the plist surgery: dates, entitlements, DeveloperCertificates
  python3 - "$WORK/$name.plist" "$FUTURE_ISO" "$NOW_ISO" "$CERT_B64" <<'PY'
import re, sys, textwrap
path, exp, now, cert_b64 = sys.argv[1:]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()

def bump(key, value, blob):
    return re.sub(
        r"(<key>" + re.escape(key) + r"</key>\s*<date>)[^<]*(</date>)",
        r"\g<1>" + value + r"\g<2>",
        blob, count=1)

text = bump("ExpirationDate", exp, text)
text = bump("CreationDate",   now, text)

# ---- inject missing entitlements ------------------------------------------
EXTRA = """
    <key>com.apple.developer.applesignin</key>
    <array><string>Default</string></array>
    <key>com.apple.developer.background-tasks.continued-processing.gpu</key>
    <true/>
    <key>com.apple.developer.communication-notifications</key>
    <true/>
    <key>com.apple.developer.usernotifications.filtering</key>
    <true/>
    <key>com.apple.developer.usernotifications.communication</key>
    <true/>
    <key>com.apple.developer.siri</key>
    <true/>
    <key>com.apple.developer.pushkit.unrestricted-voip</key>
    <true/>
"""
m = re.search(r"<key>Entitlements</key>\s*<dict>(.*?)</dict>", text, re.DOTALL)
if not m:
    sys.exit("no Entitlements dict in " + path)
inner = m.group(1)
add = ""
for match in re.finditer(r"<key>([^<]+)</key>", EXTRA):
    key = match.group(1)
    if ("<key>" + key + "</key>") in inner:
        continue
    node = re.search(
        r"<key>" + re.escape(key) + r"</key>\s*(?:<[^/][^>]*/>|<([^>]+)>[\s\S]*?</\1>)",
        EXTRA)
    if node:
        add += "\n    " + node.group(0)
if add:
    text = text[:m.start(1)] + inner.rstrip() + add + "\n  " + text[m.end(1):]

# ---- replace DeveloperCertificates -----------------------------------------
wrapped = "\n".join(textwrap.wrap(cert_b64, 64))
new_certs = ("<key>DeveloperCertificates</key>\n\t<array>\n\t\t<data>\n"
             + wrapped + "\n\t\t</data>\n\t</array>")
text = re.sub(
    r"<key>DeveloperCertificates</key>\s*<array>[\s\S]*?</array>",
    lambda m: new_certs,
    text, count=1)

with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY

  # 2.3 rewrap the patched plist in fresh CMS
  openssl cms -sign -in "$WORK/$name.plist" -signer "$WORK/cms.pem" -inkey "$WORK/cms.key" \
    -outform der -nodetach -out "$DST_DIR/$name" >/dev/null

  echo "refreshed $name"
done

echo "--- resulting profiles ---"
ls -la "$DST_DIR"
echo "--- p12 identity ---"
ls -la "$CRT_DIR"
echo "identity CN: $CERT_CN"
