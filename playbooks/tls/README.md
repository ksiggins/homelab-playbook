# Off-cluster TLS playbooks

These playbooks install and operate the NUC host issuer from
[specification 007](../../docs/specs/007-off-cluster-tls-trust.md). They target
only the `tls_hosts` inventory group through `mise run playbook`. That group has
no active host until the operator supplies and authorizes one.

The TLS command family accepts only the `production` inventory. The gateway
rejects staging and frozen inventory selections because this implementation has
one fixed production state and ACME policy. A separate staging workflow needs
its own reviewed state roots, inventory registration, and CA policy.

- `provision.yml` validates the host and declared allocation before mutation,
  installs the fixed issuer and coordinator, and reconciles the timer state.
- `renew.yml` starts the fixed root `homelab-tls-renew.service`. The unit runs
  the no-argument coordinator with a one-hour outer timeout. The blocking start
  also waits for a reconciliation already started by the timer and returns its
  final result.
- `verify.yml` observes the installed boundaries, active publication, and every
  declared TLS endpoint. It does not request or publish a certificate.

All actions require key-only SSH as the `ansible` account and passwordless
sudo. The gateway rejects password inputs and task-selection options that can
skip preflight checks.

## Required inputs

Declare these public values for the selected host:

```yaml
tls_automation_namespace: infra.example.com
tls_automation_email: acme@example.com
tls_automation_reader_gid: 2001
tls_automation_endpoints:
  - hostname: modem.infra.example.com
    address: 192.0.2.10
    port: 443
  - hostname: room-alert.infra.example.com
    address: 192.0.2.10
    port: 443
tls_automation_issuer_uid: 2010
tls_automation_issuer_gid: 2010
tls_automation_timer_enabled: false
```

The examples are synthetic. `tls_automation_namespace` must be one `infra.*`
namespace beneath the registered domain. The role derives the sole certificate
SAN as `*.<namespace>`. Each endpoint hostname must be directly beneath that
namespace and each address must be a private unicast IP literal.

The reader GID must already exist and must differ from both issuer IDs. Assign
an unused, stable UID and GID for `svc-acme`. The role records the allocation in
`/etc/homelab-tls/.issuer-account.json`. It rejects identity collisions,
partial account state, allocation changes, and an existing account without the
matching root-owned record.

Supply `tls_automation_cloudflare_token` only through operator-managed SOPS
inventory. It is written to `/etc/homelab-tls/cloudflare-token` as `root:root`
mode `0600` and is exposed to the issuer only through systemd
`LoadCredential`. If the variable is omitted while the timer is disabled, the
role preserves any existing credential file and can install a credential-free
capability. The host does not need an age identity for routine renewal.

## Disabled installation and bootstrap

The timer defaults to disabled. A disabled provisioning run does not require a
credential or `/usr/local/libexec/homelab-tls-caddy`. It installs pinned lego
5.4.1, the Python runtime, fixed launchers, state boundaries, and systemd units.
It does not contact an ACME server, publish a certificate, or create a Caddy
adapter.

Issue #25 must install `/usr/local/libexec/homelab-tls-caddy`. The adapter has
three fixed actions: `validate <root-owned-candidate-directory>`, `reload`, and
`deactivate`. It must validate Caddy's real candidate access and configuration,
force the service to reopen certificate files, and prove the route inactive
after a failed first publication. The TLS role does not assume a Caddy service
name, user, group, configuration model, or reload command. The root coordinator
unit can write only `/var/lib/homelab-tls`; the adapter must work within that
boundary and the Caddy deployment from issue #25.

Use this sequence for the first certificate:

1. Provision with `tls_automation_timer_enabled: false`. The credential can be
   omitted for this capability-only step.
2. Install the issue #25 adapter and provide the protected Cloudflare token.
   Provision again with the timer still disabled to install the credential.
3. Explicitly authorize and run one renewal:

   ```bash
   mise run playbook -- tls renew production --limit <host>
   ```

4. Verify the active certificate and all declared endpoints:

   ```bash
   mise run playbook -- tls verify production --limit <host>
   ```

5. After bootstrap succeeds, explicitly authorize ongoing renewal, set
   `tls_automation_timer_enabled: true`, and run provisioning again. Provision
   performs the same full observational verification before it enables and
   starts the twice-daily timer.

Timer enablement fails closed if the credential, fixed adapter, active
generation, clean transaction state, unit metadata, or endpoint verification
is unavailable. Do not enable the timer to bootstrap the first certificate.
The issuer service has a 15-minute request timeout. The root reconciliation
service has a one-hour timeout so serialized recovery, issuance, activation,
endpoint checks, and rollback remain inside one finite unit boundary.

## Recovery and evidence boundary

If a replacement and its rollback both fail, the journal retains the replacement
for a later bounded retry. Recovery repeats certificate and adapter checks and
fresh TLS verification. A successful retry does not start issuance and preserves
both prior failure outcomes in the current status. Invalid retained material
keeps recovery blocked; do not remove the journal to bypass it.

`status.json` under the private state directory records the current attempt. An
`in_progress` attempt can indicate an interrupted operation; it is not evidence
of successful completion. Observational verification does not change status.

Keep encrypted backups of `/var/lib/homelab-tls-issuer` ACME account state and
`/var/lib/homelab-tls` publication state. Preserve numeric ownership and private
key confidentiality. On a replacement host, restore administrative access and
the OS baseline first. Reconcile the role with the timer disabled, restore
state when available, install the issue #25 adapter, run one authorized renewal
if necessary, verify the active endpoints, and only then enable the timer.

If ACME account state is unavailable, restore independent DNS, time, outbound
network, and SOPS credential access before an explicitly authorized renewal.
Account for CA rate limits. Direct appliance access remains the recovery path
when Caddy or local DNS is unavailable.

The registered `system_maintenance/baseline` Molecule scenario installs the
disabled capability on disposable Debian 13 and Rocky Linux 9 hosts. It checks
packages, identity isolation, file metadata, parsed systemd units, the missing
adapter failure, manual-start waiting for successful and failed synthetic jobs,
and the installed runtime with distribution Python and
cryptography. It makes no ACME request and does not prove live Caddy reload,
endpoint behavior, boot persistence, or production renewal.
