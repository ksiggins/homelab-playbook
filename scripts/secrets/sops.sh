#!/usr/bin/env bash
set -euo pipefail

# SOPS searches default age/SSH files even when age_key_cmd is configured.
# Isolate its search; restore the operator context only for retrieval/editor.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
sops_context="$(mktemp -d)"
trap 'rm -rf -- "$sops_context"' EXIT
chmod 0700 "$sops_context"
export HOMELAB_SOPS_ORIGINAL_HOME="${HOME:-}"
export HOMELAB_SOPS_ORIGINAL_XDG="${XDG_CONFIG_HOME:-}"
export HOMELAB_SOPS_HAD_XDG="${XDG_CONFIG_HOME+x}"
cat > "$sops_context/context.sh" <<'CONTEXT'
#!/usr/bin/env bash
set -euo pipefail
export HOME="$HOMELAB_SOPS_ORIGINAL_HOME"
if [[ "$HOMELAB_SOPS_HAD_XDG" == x ]]; then
  export XDG_CONFIG_HOME="$HOMELAB_SOPS_ORIGINAL_XDG"
else
  unset XDG_CONFIG_HOME
fi
exec "$@"
CONTEXT
chmod 0700 "$sops_context/context.sh"

key_command="${SOPS_AGE_KEY_CMD:-\"$repo_root/scripts/secrets/age-keychain.sh\"}"
editor_command="${SOPS_EDITOR:-${EDITOR:-vi}}"
unset SOPS_AGE_KEY SOPS_AGE_KEY_FILE SOPS_AGE_SSH_PRIVATE_KEY_FILE SOPS_AGE_SSH_PRIVATE_KEY_CMD
export SOPS_AGE_KEY_CMD="\"$sops_context/context.sh\" $key_command"
export SOPS_EDITOR="\"$sops_context/context.sh\" $editor_command"
export HOME="$sops_context"
export XDG_CONFIG_HOME="$sops_context"

sops "$@"
