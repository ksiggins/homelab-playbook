# Podman foundation playbooks

These playbooks establish reusable rootless Podman capability on Debian 13 and
Rocky Linux 9 hosts that already have the OS baseline. They target
`podman_hosts` through the canonical `mise run playbook` gateway.

- `provision.yml` installs official distribution prerequisites, reconciles
  explicitly declared service identities and directories, and verifies them.
- `verify.yml` observes capability, identity mappings, permissions, password
  locks, sudo denial, and user-manager state without repairs or container runs.

Both actions require the existing key-only `ansible` account with passwordless
sudo. Provisioning includes verification; a second verify run is optional and
useful for later drift checks. Neither action deploys application containers.

The production account list is empty. Later service initiatives declare their
own accounts and add secret-free, root-owned Quadlets. No service uses the
administrative `ansible` account as its runtime identity.

Follow the [Podman foundation guide](../../docs/guides/podman-foundation.md) for
inputs, ownership, lifecycle, recovery, and evidence limits. See
[specification 006](../../docs/specs/006-podman-quadlet-foundation.md) for design.

The registered `system_maintenance/baseline` Molecule scenario exercises the
foundation with two synthetic accounts on both supported distributions. It
checks idempotence, permission separation, the installed Quadlet generator,
and drift detection. These checks do not prove a rootless application container
can run on production, survive physical boot, or enforce runner network and
resource policy.
