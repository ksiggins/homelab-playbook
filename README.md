# Homelab Playbook

Ansible automation for provisioning and maintaining off-cluster homelab hosts.

## Prerequisites

Install [Mise](https://mise.jdx.dev/), Git, and SSH configuration appropriate
for the hosts you are explicitly authorized to operate.

## Bootstrap

After checkout, install the pinned tools, then install the locked controller and
Galaxy dependencies. Repeat both commands after a tool or dependency change:

```bash
mise install
mise run bootstrap
```

## Repository layout

`playbooks/` contains host automation, `roles/` contains reusable Ansible roles,
and `inventory/` contains environment inventories. The
[documentation index](docs/README.md) links current guides, references, and
durable specifications. Transient implementation plans belong in `.tmp/plans/`.

## Running playbooks

Run playbooks through the repository interface:

```bash
mise run playbook -- <playbook> <action> <inventory> [ansible-args...]
```

The repository-root alias is an equivalent thin forwarding wrapper:

```bash
./run-playbook <playbook> <action> <inventory> [ansible-args...]
```

Execute against production or staging only with explicit operator direction.

### OS baseline commands

These commands target Debian 13 and Rocky Linux 9 hosts in `os_managed`.
The examples select the current production host, `nuc4`. Complete the
[managed host onboarding guide](docs/guides/managed-host-onboarding.md) first
for manual host preparation, SSH access, inventory, and Vault setup.

| Command | Purpose |
| --- | --- |
| `mise run playbook -- os inspect production --limit nuc4 --ask-vault-pass` | Read a basic OS fact snapshot. |
| `mise run playbook -- os provision production --limit nuc4 --ask-vault-pass` | Perform a full update, reconcile the complete baseline, reboot if needed, and verify. |
| `mise run playbook -- os maintain production --limit nuc4 --ask-vault-pass` | Perform a later full package update, reboot if needed, and verify without reapplying configuration. |
| `mise run playbook -- os verify production --limit nuc4 --ask-vault-pass` | Check the complete effective baseline without changes. |

Provisioning and maintenance include verification. Use standalone verification
at any time to check for drift; use provisioning to reconcile it. A successful
provisioning run includes a full update, so do not immediately follow it with
maintenance. Native daily security updates remain separate from explicit full
maintenance; no host-local recurring full-update scheduler exists.

See the [OS playbook README](playbooks/os/README.md) for inputs, composition,
and validation boundaries.

### Podman foundation commands

Run these after establishing the OS baseline. They target `podman_hosts`;
`nuc4` is the current production member. Inventory parsing still requires the
OS Vault password even though the foundation does not consume secret values.

| Command | Purpose |
| --- | --- |
| `mise run playbook -- podman provision production --limit nuc4 --ask-vault-pass` | Install Podman prerequisites, reconcile declared service accounts and directories, and verify. |
| `mise run playbook -- podman verify production --limit nuc4 --ask-vault-pass` | Check installed capability, declared identities, permissions, and user-manager state without changes. |

Provisioning includes verification. Standalone verification is useful for later
drift checks, including after OS maintenance. Both verifiers stop at the first
failed assertion and do not repair drift.

The production service-account list is empty, so these commands currently
establish and check host capability and shared directories. They deploy no
applications. See the [Podman playbook README](playbooks/podman/README.md) for
account inputs, ownership, failure recovery, and validation boundaries.

## Inventories

Select one of these inventory arguments:

- `production` contains the active `nuc4` host in `os_managed`.
- `staging` contains no hosts; it retains non-active Semaphore deployment and
  backup inputs for future work.
- `frozen/k3s` retains the non-active K3s inventory.

Production and staging are operator inputs. Validation parses public-only
inventory mirrors and does not connect to their hosts.
Each inventory directory stores its static host and group topology in
`hosts.yml`; public variables remain under `group_vars/`.

## Secrets

SOPS encrypts inventory secrets to public age recipients. The operator's
dedicated repository identity lives in the macOS login Keychain; its encrypted
backup and backup passphrase remain outside every checkout. Future automation
controllers use separate identities. See the [SOPS secrets guide](docs/guides/sops-secrets.md)
for workstation setup, recovery, editing, and recipient changes.

Public group variables live in `vars.yml`; version pins in `versions.yml` are
public as well. Encrypted variables use sibling `secrets.sops.yml` files. The
active boundary is `inventory/production/group_vars/os_managed/`.
`inventory/production/host_vars/nuc4/vars.yml` contains public hostname
metadata. The sibling protected file contains identity and access inputs.
Retained Semaphore inputs are under
`inventory/staging/group_vars/semaphore/`, and retained K3s variables are under
`inventory/frozen/k3s/group_vars/`.

The operator completed the one-way conversion of production, staging, and
frozen inventory. SOPS is the only current inventory encryption format.
Agents and CI never decrypt or inspect protected inventory.

## Validation

Use focused validation while iterating, then run change-directed validation before
claiming completion:

```bash
mise run validate:fast
mise run validate:ansible
mise run validate:secrets
mise run test:secrets
mise run ci:changed
```

`ci:changed` classifies committed and working-tree changes and runs the minimum
required depth. Use `mise run ci` to force all currently implemented offline
validation. `validate:secrets` checks ciphertext structure and public recipient
metadata. `test:secrets` uses only ephemeral identities and fixtures. Pull-request
validation is offline and receives no live identity.

### Molecule tests

`mise run test:molecule -- system_maintenance/default` runs the repository's
rootless Podman scenario for Debian 13 and Rocky Linux 9. The same platform set
runs locally and in GitHub's native AMD64 matrix.

`mise run test:molecule -- system_maintenance/baseline` runs complete Debian
and Rocky composition. CI runs both platforms for both scenarios as four exact
selector-and-platform matrix jobs. Container results do not prove physical
reboot, host-kernel enforcement, real network reachability, or Semaphore
scheduling and notification delivery.

## GitHub main protection

Changes reach `main` through a feature branch, a current pull request, the
required `merge-gate`, and a squash merge. Repository-owned commands can inspect
or preview the live protection state:

```bash
mise run github-protection:check
mise run github-protection:plan
```

Live checks require authenticated repository-administration access and remain
outside CI. Applying a plan is a separately authorized, repository-bound action;
the plan and its confirmation value do not grant that authority. See the
[GitHub main protection guide](docs/guides/github-main-protection.md) for the
exact Ruleset, guarded apply procedure, UI inspection, and recovery steps.

## Frozen K3s

The retained K3s source is frozen. It receives static validation only; live
verification remains operator-run and is not CI evidence.

## License

This repository is licensed under [Apache-2.0](LICENSE).
