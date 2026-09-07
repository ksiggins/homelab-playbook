# Podman and Quadlet foundation

Use this foundation after completing the [OS baseline](managed-host-onboarding.md).
The current production target is `nuc4` in `podman_hosts`. Its account list is
empty: this initiative installs Podman capability without deploying Forgejo,
Semaphore, a runner, Tailscale, or their application state.

## Operator commands

Run local dependency bootstrap after checkout:

```bash
mise run bootstrap
```

The following live commands require explicit authorization for the exact
playbook, action, inventory, host limit, and arguments immediately before
execution. Inventory parsing can require the OS Vault password even though the
foundation does not consume secret values.

```bash
mise run playbook -- podman provision production --limit nuc4 --ask-vault-pass
mise run playbook -- podman verify production --limit nuc4 --ask-vault-pass
```

Provisioning checks prerequisites, installs official distribution packages,
reconciles declared accounts, and verifies the result. A successful run already
includes verification. Run standalone verification later to detect drift
without package changes, repairs, image pulls, or service starts.

Both commands use the existing `ansible` administrative account and
non-interactive sudo. Task selection and password-based SSH/sudo controls are
rejected so they cannot bypass required checks. The gateway remains the only
repository playbook execution interface. `verify` is an observational action,
not an Ansible check-mode simulation of provisioning.

## Declaring a later service account

Each domain service gets its own rootless account and matching private group.
An application and its dedicated database may share that account. A runner
must have its own account and must not share management credentials or storage.

The following declaration is a synthetic example, not an allocation for a
future production service:

```yaml
podman_foundation_accounts:
  - name: svc-example
    uid: 2001
    gid: 2001
    subuid_start: 200000
    subuid_count: 65536
    subgid_start: 200000
    subgid_count: 65536
```

Names begin with `svc-` or `ci-`. The primary group has the same name as its
account. UID and GID are explicit, stable, positive numeric values. Each
subordinate range reserves at least 65536 numeric identities for container
users or groups; it does not create thousands of login accounts. Related
containers use their service account's allocation. Different accounts' ranges
must not overlap existing subordinate allocations or host identities.

Before declaring production values, inspect host allocations through an
operator-authorized read-only workflow. The foundation validates all declared
identities against effective passwd/group lookup and the file-based subordinate
provider. It rejects conflicts, existing account migrations, supplementary
group access, and ambiguous mappings instead of choosing replacement IDs.
Non-file subordinate providers require a separately reviewed integration.

A root-owned `.foundation-account.json` record in the UID-scoped directory
identifies foundation-owned accounts and fixes their allocations. Matching
names alone do not authorize adoption of a pre-existing account. New system
accounts suppress automatic subordinate allocation; the foundation installs
exactly the declared ranges and preserves unrelated entries.

## Ownership and application responsibilities

| Path | Owner:group | Mode |
| --- | --- | --- |
| `/etc/containers/systemd/users/<UID>/` | `root:<account>` | `0750` |
| Quadlet definitions and ownership record | `root:<account>` | `0640` |
| `/var/lib/<account>/` | `<account>:<account>` | `0700` |

The private home holds that service's runtime state. Podman uses its default
rootless storage below `.local/share/containers/storage` when the service first
runs Podman. The foundation does not initialize application storage or create
application data directories. Later service roles own their data layout and
container-user mappings. They must preserve subordinate ownership within data,
not recursively change it to the host account UID.

Service accounts have locked passwords, a non-login shell, no SSH keys or sudo,
and persistent user systemd managers through logind lingering. Human operators
continue to log in as `ansible` and administer services through sudo.

Later service roles install root-owned Quadlets in the UID-scoped directory,
validate them using the installed generator, reload that account's user manager,
and start only their own services. Boot-started user services declare:

```ini
[Install]
WantedBy=default.target
```

Generated `.service` files are transient systemd outputs. Do not edit them or
use `systemctl enable` as a substitute for the Quadlet install section. Do not
place per-service definitions directly in the all-users Quadlet directory.

Quadlet definitions contain no secrets. Mode `0640` is defense in depth, not
credential storage. Later service designs choose credential delivery under the
current Ansible Vault boundary. Pin images and application versions in Git;
do not enable automatic image updates. This foundation does not enable API
sockets, image pruning, application ports, or privileged-port exceptions.

Root-owned definitions cannot be edited by the service identity, but that
identity can control its own user manager. Account separation does not replace
container mount restrictions, runner resource limits, or network policy.

## Verification, failures, and recovery

`podman verify` checks the installed executable prerequisites and cgroup v2,
then checks each declared account, subordinate mapping, private directory,
definition metadata, password lock, sudo denial, and active lingering manager.
It stops on the first failed assertion. It does not produce a complete list of
all drift or prove application health. With an empty account list it checks
only host capability and shared boundaries.

If provisioning fails during account creation, inspect the account, group,
subordinate entries, home, and ownership record before retrying. A partially
created account without complete mappings or an ownership record stops the
next run for operator migration review. Do not bypass this by deleting data or
renumbering the account. Correct only the failed transaction with explicit
operator authorization after confirming which state it owns.

Changing an established UID/GID or subordinate range requires a separately
reviewed migration with stopped workloads and ownership-aware backups. Removing
an account declaration does not delete the account, mappings, or data; retirement
and ID reuse are separate operator actions.

Keep an external controller, Git checkout, Vault access, and trusted console or
rescue path available independently of NUC #4. Later service backup procedures
must preserve numeric IDs and supply recoverable data and credentials outside
the host. Neither NUC #4 nor Talos may depend solely on a service on NUC #4 for
recovery. No application restore is proven by this foundation.

## Development evidence

```bash
mise run validate:fast
mise run validate:ansible
mise run test:molecule -- system_maintenance/baseline
mise run ci:changed
```

The baseline scenario creates two synthetic accounts in disposable Debian and
Rocky containers. It checks reconciliation idempotence, cross-account access
denial, administrator-owned Quadlet generation, and detection of deliberately
introduced permission drift. Cleanup belongs to the bounded Molecule lifecycle.

These tests do not pull or start the synthetic application image. Nested
container evidence does not prove rootless application execution on the real
host, physical boot persistence, kernel enforcement, recovery access, or runner
network isolation. Those require separately authorized live evidence when a
service is instantiated. Do not weaken the OS baseline to obtain nested-container
results.
