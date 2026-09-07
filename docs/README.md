# Documentation

Use the [root README command reference](../README.md#running-playbooks) for
routine playbook operations. Guides cover setup and recovery procedures.

## Guides

- [GitHub main protection](guides/github-main-protection.md) — Inspect, verify,
  and recover the repository's protected-branch settings.
- [Managed host onboarding](guides/managed-host-onboarding.md) — Prepare,
  provision, verify, maintain, and recover an off-cluster Ansible-managed host.
- [SOPS secrets](guides/sops-secrets.md) — Set up and recover the operator age
  identity, edit protected inventory, and manage recipients.

## Reference

- [Repository command lifecycle](reference/repository-command-lifecycle.md) —
  Classify command behavior, safeguards, execution authority, and evidence.

## Specifications

- [001 — Agentic development modernization](specs/001-agentic-development-modernization.md)
  — Defines the repository's agentic workflow, safety controls, and validation
  architecture.
- [002 — Multi-OS Molecule validation](specs/002-multi-os-molecule-validation.md)
  — Defines deterministic Debian and Rocky Linux container validation.
- [003 — OS maintenance and security baseline](specs/003-os-maintenance-security-baseline.md)
  — Defines supported host maintenance, security policy, verification, and
  reboot behavior.
- [004 — Managed host onboarding](specs/004-managed-host-onboarding.md) —
  Defines the reusable onboarding design and the first active `os_managed`
  production host.
- [005 — SOPS and age inventory secrets](specs/005-sops-age-secrets.md) —
  Defines the one-way migration from Ansible Vault and the current secret
  loading, identity, recovery, and validation contract.
- [006 — Podman and Quadlet foundation](specs/006-podman-quadlet-foundation.md) —
  Defines separate service-account ownership, stable identity allocations, and
  reusable rootless container conventions without deploying applications.
