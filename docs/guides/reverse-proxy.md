# Shared private HTTPS operations

Caddy provides a host-level private HTTPS entry point for separately managed
applications. This guide describes the issue #25 proxy interface. Issue #5 owns
production certificate issuance, renewal, deployment, and recovery.

## Prerequisites

Establish the [OS baseline](managed-host-onboarding.md) and retain a working
external controller and console path. Use the repository's locked controller
dependencies and [SOPS setup](sops-secrets.md). The proxy must never depend on
Semaphore, Forgejo, or Kubernetes to recover itself.

Production is declared with empty bind-address, client-source, and route lists.
Provisioning that state creates an admin-only service and exposes no HTTPS.
Before activating a route, the operator supplies its private inventory inputs,
DNS pointing to the selected private host address, and trusted certificate pair.
Repository development does not inspect protected production values.

## Declare routes and network access

The following is a synthetic example, not production input:

```yaml
reverse_proxy_bind_addresses:
  - 10.20.30.40
reverse_proxy_client_sources:
  - 10.20.0.0/16
reverse_proxy_routes:
  - hostname: app.example.test
    backend_port: 18080
    certificate_name: app
```

Enter actual values through the existing operator-owned protected host inventory
process. Keep exact deployment inputs out of public files. Declare the complete
desired route set; it replaces the prior set. Do not supply Caddyfile fragments,
arbitrary upstream URLs, or credentials in routes.

An application publishes its backend only on `127.0.0.1`, for example through
its own Quadlet's loopback port publication. It serves HTTP without managing
TLS or owning port 443. Caddy uses normal HTTP and WebSocket reverse proxying.
Host loopback limits remote reachability but remains reachable by other local
accounts; application authentication remains the application's responsibility.

HTTPS accepts only declared private sources and bind addresses. The baseline
firewall owns the source-scoped TCP/443 rules in both runtime and permanent
policy. The proxy exposes neither HTTP on TCP/80 nor HTTP/3 on UDP/443.
Do not open backend ports as firewall service extensions.

## Supply certificates

The externally managed filesystem contract is:

```text
/etc/caddy/tls/app/
  version-001/
    fullchain.pem
    privkey.pem
  current -> version-001
```

Directories are `root:caddy` mode `0750`; certificate and key files are
`root:caddy` mode `0640`. The `current` symlink is also owned by `root:caddy`.
The version pointer must remain inside its certificate
directory. Supply complete immutable versions before selecting one, with platform
labels that permit Caddy to read them. The proxy cannot write these files and
receives no issuer or Cloudflare credentials.

The certificate deployment transaction and configuration activation share
`/run/lock/homelab-reverse-proxy.lock`. Issue #5 must serialize selection,
validation, reload, and served-certificate verification under this lock. Retain
the previous version until verification succeeds; restore the previous pointer
and reload it on failure. A certificate deployment interrupted across a reboot
requires the certificate owner's recovery procedure.

The root-owned `/usr/local/libexec/homelab-reverse-proxy reload` entry point
acquires the lock, validates as Caddy, and forces reload even if configuration
text has not changed. It requires an already active service. The integration
forms `reload --lock-held` and `verify --lock-held` require the existing exclusive
lock inherited on file descriptor 9; they do not obtain authority merely from
a command-line flag. The certificate workflow must retain the lock through
its post-reload checks.

The helper never prints private key material or configuration payloads. A missing,
unreadable, mismatched, expired, or hostname-incompatible pair prevents activation.
It does not create a substitute production certificate.

## Provision and verify

After explicit operator authorization for the exact target and action:

```bash
mise run playbook -- reverse-proxy provision production --limit nuc4
```

Provisioning includes verification. Later observational verification uses:

```bash
mise run playbook -- reverse-proxy verify production --limit nuc4
```

Reconfirm each live execution's playbook, action, inventory, host limit, and extra
arguments immediately before running it. The gateway rejects password credential
and task-selection controls. Use complete reconciliation after correcting failed
preconditions instead of bypassing the failed task.

Use normal host diagnostics through the operator's authorized host session:

```bash
systemctl status caddy
journalctl -u caddy
```

Keep operational output private when it contains deployment names or addresses.
From an approved client, verify the actual hostname's trusted HTTPS response and
application login. Separately verify denial from outside the allowed network.
Local verification alone does not establish network reachability or DNS accuracy.

## Package upgrades

Caddy is an unpinned system package. Debian uses its native repository; Rocky
uses signed EPEL packages. Proxy provisioning installs missing packages without
upgrading all packages. Existing OS provisioning and maintenance own upgrades.
Do not replace `/usr/bin/caddy` manually or run the Caddy self-upgrade command.

Debian's daily unattended policy permits Debian Security updates. Rocky's daily
policy selects updates classified as security by repository metadata. Neither
policy promises that every upstream Caddy release will install automatically.
Operator-triggered full OS maintenance includes ordinary package updates.

A binary upgrade can restart Caddy and interrupt all proxied services briefly.
After maintenance, run authorized proxy verification and a client HTTPS check.
Route and certificate updates use reload instead of process restart. Successful
reloads can close established WebSockets, which application clients reconnect.
There is no promise of seamless sessions across package upgrades or reboot.

## Failed activation and recovery

Configuration activation validates a staged candidate before replacing the boot
configuration. A failed reload restores the previous committed configuration on
disk as well as the working runtime configuration when needed. A pending record
is recovered before Caddy starts on the next boot. Do not manually delete recovery
records to bypass an unresolved failure.

On first provisioning the committed baseline is admin-only. If the first route
activation fails, that baseline remains available without HTTPS exposure. Correct
the reported configuration, ownership, or certificate condition and rerun the
authorized provisioning action. If recovery itself fails, retain its diagnostic
and inspect the target through the independent administration path before retrying.

Package-version rollback is a separate operator action. Retain or obtain a
trusted prior distribution package when a package regression requires it; the
configuration transaction does not downgrade installed software automatically.

Reconstruct a lost host from Git, the OS baseline, and separately recovered
certificate material. Caddy's private cache and autosaved JSON are not the source
of truth: systemd always starts the explicit managed Caddyfile. Restore application
state through each application's own recovery procedure.

Removing a test route does not delete externally owned TLS material. A registered
disposable acceptance test owns and removes its synthetic certificates and backend
processes; production certificate retirement belongs to issue #5.
