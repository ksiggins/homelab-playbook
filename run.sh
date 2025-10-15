#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  run.sh <playbook> <task> <inventory> [ansible-args...]

Arguments:
  <playbook>     The playbook name under playbooks/ (e.g., podman)
  <task>         The task filename without extension (e.g., install, uninstall, verify)
  <inventory>    The inventory environment (e.g., staging, production)
  [ansible-args] Optional extra args passed to ansible-playbook (e.g. --check, -vvv, --limit host1)

Examples:
  run.sh podman install staging
  run.sh podman verify production -vvv
  run.sh podman uninstall staging --limit base.local.aerisllc.com

Notes:
  - Must be run from project root (where playbooks/ and inventory/ directories exist).
  - Single hosts must be specified via --limit against a valid inventory environment.
EOF
  echo
  echo "Available playbooks:"
  find playbooks -maxdepth 1 -mindepth 1 -type d -exec basename {} \; | sort
  exit 0
}

# No args → usage + playbooks
if [ $# -eq 0 ]; then
  usage
fi

PLAYBOOK_NAME="$1"
PLAYBOOK_DIR="playbooks/${PLAYBOOK_NAME}"

# 1 arg → list tasks in playbook dir
if [ $# -eq 1 ]; then
  if [ ! -d "$PLAYBOOK_DIR" ]; then
    echo "Error: Playbook directory '$PLAYBOOK_DIR' not found."
    exit 1
  fi
  echo "Available tasks for playbook '${PLAYBOOK_NAME}':"
  find "$PLAYBOOK_DIR" -maxdepth 1 -type f -name '*.yml' -exec basename {} .yml \; | sort
  exit 0
fi

TASK="$2"

# 2 args → list inventories
if [ $# -eq 2 ]; then
  if [ ! -d "inventory" ]; then
    echo "Error: inventory/ directory not found."
    exit 1
  fi
  echo "Available inventories:"
  find inventory -mindepth 1 -maxdepth 1 -type f -exec basename {} \; | sort
  exit 0
fi

# 3 or more args → run playbook
INVENTORY_ENV="$3"
shift 3
EXTRA_ARGS="$*"

PLAYBOOK_FILE="${PLAYBOOK_DIR}/${TASK}.yml"
INVENTORY_FILE="inventory/${INVENTORY_ENV}"

if [ ! -f "$PLAYBOOK_FILE" ]; then
  echo "Error: Playbook file '$PLAYBOOK_FILE' not found."
  exit 1
fi

if [ ! -f "$INVENTORY_FILE" ]; then
  echo "Error: Inventory directory '$INVENTORY_FILE' not found."
  exit 1
fi

echo ">>> Running playbook: $PLAYBOOK_FILE"
echo ">>> Inventory: $INVENTORY_FILE"

ansible-playbook -i "$INVENTORY_FILE" "$PLAYBOOK_FILE" $EXTRA_ARGS
