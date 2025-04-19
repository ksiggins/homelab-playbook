#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
CSV_FILE="$SCRIPT_DIR/manifest.csv"
TARGETS=("$@")

usage() {
  cat <<EOF
Usage: $(basename "$0") [ORBNAME1 [ORBNAME2 ...]]

Recreates orbs based on entries in the manifest.csv file.

Arguments:
  ORBNAME       Optional. Format: <distro><version> (e.g. rocky9, debian12).
                If omitted, all orbs in the manifest will be recreated.

Examples:
  $(basename "$0") rocky9              Recreate only the 'rocky9' orb
  $(basename "$0") debian12 arch       Recreate multiple orbs
  $(basename "$0")                     Recreate all orbs from manifest

Options:
  -h, --help      Show this help message and exit
EOF
  exit 0
}

is_target() {
  local name="$1"
  [[ ${#TARGETS[@]} -eq 0 ]] && return 0
  for t in "${TARGETS[@]}"; do
    [[ "$t" == "$name" ]] && return 0
  done
  return 1
}

recreate_orb() {
  local distro="$1"
  local version="$2"
  local arch="$3"
  local user="$4"
  local name="${distro}${version}"

  is_target "$name" || return

  local image
  [[ -n "$version" ]] && image="${distro}:${version}" || image="${distro}"

  orb delete --force "$name"
  orb create --user "$user" --arch "$arch" "$image" "$name"
}

main() {
  case "$1" in
    -h|--help)
      usage
      ;;
  esac

  tail -n +2 "$CSV_FILE" | while IFS=, read -r distro version arch user; do
    recreate_orb "$distro" "$version" "$arch" "$user"
  done
}

main "$@"