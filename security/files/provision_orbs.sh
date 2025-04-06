#!/bin/bash

# Determine the directory of the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

# CSV file containing the manifest
CSV_FILE="$SCRIPT_DIR/manifest.csv"

# Delete all orbs forcefully
orb delete --all --force

# Read the CSV file and create orbs, skipping the first line
tail -n +2 "$CSV_FILE" | while IFS=, read -r distro version arch user; do
    orb create --user "$user" --arch "$arch" "$distro:$version" "$distro$version"
done
