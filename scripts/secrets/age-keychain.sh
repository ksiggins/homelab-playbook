#!/usr/bin/env bash
set -euo pipefail

platform_name() {
  /usr/bin/uname -s
}

stdout_is_terminal() {
  [[ -t 1 ]]
}

read_identity() {
  /usr/bin/security find-generic-password \
    -a operator \
    -s homelab-playbook.sops.age \
    -w \
    "$HOME/Library/Keychains/login.keychain-db"
}

main() {
  if [[ $# -ne 0 ]]; then
    printf '%s\n' 'Error: this helper does not accept arguments' >&2
    return 2
  fi
  if [[ "$(platform_name)" != Darwin ]]; then
    printf '%s\n' 'Error: the age identity is available only from macOS Keychain' >&2
    return 1
  fi
  if stdout_is_terminal; then
    printf '%s\n' 'Error: refusing to write an age identity to a terminal' >&2
    return 1
  fi

  local identity
  if ! identity="$(read_identity 2>/dev/null)" || \
    [[ ! "$identity" =~ ^AGE-SECRET-KEY-1[0-9A-Z]+$ ]]; then
    printf '%s\n' 'Error: the age identity is unavailable from macOS Keychain' >&2
    return 1
  fi
  printf '%s\n' "$identity"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
