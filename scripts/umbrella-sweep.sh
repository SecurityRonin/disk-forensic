#!/usr/bin/env bash
# umbrella-sweep.sh — reconciliation gate for the disk-forensic umbrella map.
#
# DISCOVERY, not a manual list: scan the fleet for every repo that is a forensic-vfs
# reader/PRODUCER — signalled by the optional adapter feature `vfs = ["dep:forensic-vfs"]`
# in its Cargo.toml on ANY branch — then assert each is REGISTERED in this repo's
# umbrella map (docs/umbrella-members.txt AND docs/validation-inventory.md).
#
# The adapter-feature signal is precise: it matches producers (readers exposing an
# ImageSource/VolumeSystem/CryptoLayer/FileSystem adapter) and NOT consumers, which
# depend on forensic-vfs non-optionally and only USE its traits (issen, disk-forensic,
# 4n6mount, browser-forensic). "impl <Contract> for" is too loose — it also matches a
# consumer's test MockFs / trait re-export.
#
# "Do the right thing": a discovered-but-unregistered reader means disk-forensic's
# map silently under-claims coverage — so this BLOCKS the publish (exit 1) and names
# exactly what to add. Run it before publishing disk-forensic (release gate) and
# whenever the fleet changes.
#
# Usage: scripts/umbrella-sweep.sh [FLEET_ROOT]   (default: parent dir of this repo)
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
FLEET_ROOT="${1:-$(cd "$HERE/.." && pwd)}"
MANIFEST="$HERE/docs/umbrella-members.txt"
INVENTORY="$HERE/docs/validation-inventory.md"
FEATURE_RE='vfs *= *\["dep:forensic-vfs"\]'
# Consumers + hub + the contract crate itself use forensic-vfs but are NOT readers.
CONSUMERS=" disk-forensic forensic-vfs forensic-vfs-engine forensic-vfs-mount 4n6mount issen browser-forensic "

manifest_names="$(grep -vE '^\s*#|^\s*$' "$MANIFEST" | sed 's/#.*//;s/[[:space:]]//g' | grep -v '^$' || true)"

discovered=()
for d in "$FLEET_ROOT"/*/; do
  repo="$(basename "$d")"
  [ -d "$d/.git" ] || continue
  case "$CONSUMERS" in *" $repo "*) continue;; esac
  # producer = carries the optional vfs adapter feature in a Cargo.toml (working tree:
  # the repo's current branch — for mid-migration repos that is their feat branch).
  if grep -rqsE "$FEATURE_RE" "$d"Cargo.toml "$d"core/Cargo.toml "$d"*/Cargo.toml 2>/dev/null; then
    discovered+=("$repo")
  fi
done

missing=()
for repo in "${discovered[@]}"; do
  if ! printf '%s\n' "$manifest_names" | grep -qxF "$repo"; then
    missing+=("$repo — not in docs/umbrella-members.txt"); continue
  fi
  grep -q "$repo" "$INVENTORY" || missing+=("$repo — in manifest but not in docs/validation-inventory.md")
done

echo "Discovered ${#discovered[@]} forensic-vfs contract repos under $FLEET_ROOT:"
printf '  %s\n' "${discovered[@]}" | sort
echo

if [ "${#missing[@]}" -gt 0 ]; then
  echo "❌ UNREGISTERED umbrella members — disk-forensic's map is INCOMPLETE:"
  printf '  - %s\n' "${missing[@]}"
  echo
  echo "Register each in docs/umbrella-members.txt + a row in docs/validation-inventory.md"
  echo "and reflect it in docs/assets/umbrella-architecture.svg, then re-run. Publish is BLOCKED."
  exit 1
fi
echo "✅ Every discovered forensic-vfs member is registered. Umbrella map is complete."
