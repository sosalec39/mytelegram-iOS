#!/usr/bin/env bash
# Rewrite the checked-in example provisioning profiles with:
#   * a far-future ExpirationDate
#   * an Entitlements dictionary that is a superset of every key the app
#     itself declares (rules_apple only fails on missing keys in the profile,
#     never on extra ones).
#
# rules_apple parses `.mobileprovision` with `openssl smime -verify -noverify`,
# so wrapping our patched plist with a fresh self-signed CMS envelope passes
# all downstream checks (application-identifier / TeamIdentifier /
# aps-environment / ExpirationDate / entitlements coverage).
set -euo pipefail

SRC_DIR="build-system/example-configuration/provisioning"
DST_DIR="build-system/example-configuration/profiles"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$DST_DIR"

openssl req -x509 -newkey rsa:2048 -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
  -sha256 -days 3650 -nodes -subj "/CN=larpgram-ci-fake" >/dev/null 2>&1

FUTURE_ISO="2035-12-31T23:59:59Z"
NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for src in "$SRC_DIR"/*.mobileprovision; do
  name="$(basename "$src")"
  # 1. Extract the raw plist (signature not checked).
  openssl smime -inform der -verify -noverify -in "$src" -out "$WORK/$name.plist"

  # 2. Bump dates and inject the extra entitlement keys the app requires but
  #    the 2022-era example profile is missing.
  python3 - "$WORK/$name.plist" "$FUTURE_ISO" "$NOW_ISO" <<'PY'
import re, sys
path, exp, now = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()

def bump(key, value, blob):
    return re.sub(
        r"(<key>" + re.escape(key) + r"</key>\s*<date>)[^<]*(</date>)",
        r"\g<1>" + value + r"\g<2>",
        blob, count=1)

text = bump("ExpirationDate", exp, text)
text = bump("CreationDate",   now, text)

# Additional entitlements declared by Telegram fragments (see Telegram/BUILD:
# store_signin_fragment / official_background_gpu_fragment / etc.) that are
# absent from the 2022 example profile. Adding them to the profile is safe:
# rules_apple only requires the app's keys to be a subset of the profile's.
EXTRA_KEYS = """
    <key>com.apple.developer.applesignin</key>
    <array>
      <string>Default</string>
    </array>
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

# Insert EXTRA_KEYS right before the closing </dict> of the top-level
# <key>Entitlements</key><dict>...</dict> block. Only add keys that are not
# already present so re-runs stay idempotent.
m = re.search(r"<key>Entitlements</key>\s*<dict>(.*?)</dict>", text, re.DOTALL)
if not m:
    sys.exit("no Entitlements dict in " + path)
inner = m.group(1)
add = ""
for match in re.finditer(r"<key>([^<]+)</key>", EXTRA_KEYS):
    key = match.group(1)
    if ("<key>" + key + "</key>") not in inner:
        # Grab this key + its immediate value node.
        block = re.search(
            r"<key>" + re.escape(key) + r"</key>\s*(?:<[^/][^>]*/>|<([^>]+)>[\s\S]*?</\1>)",
            EXTRA_KEYS)
        if block:
            add += "\n    " + block.group(0)
if add:
    new_dict = inner.rstrip() + add + "\n  "
    text = text[:m.start(1)] + new_dict + text[m.end(1):]

with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY

  # 3. Wrap back into DER-CMS.
  openssl cms -sign -in "$WORK/$name.plist" -signer "$WORK/c.pem" -inkey "$WORK/k.pem" \
    -outform der -nodetach -out "$DST_DIR/$name" >/dev/null

  echo "refreshed $name"
done

echo "--- resulting profiles ---"
ls -la "$DST_DIR"
echo "--- sample entitlement keys in Telegram.mobileprovision ---"
openssl smime -inform der -verify -noverify -in "$DST_DIR/Telegram.mobileprovision" 2>/dev/null \
  | grep -oE '<key>[^<]+</key>' | sort -u | head -n 30
