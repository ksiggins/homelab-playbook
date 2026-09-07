# Specification 007: Off-cluster TLS trust

Issue: [#5](https://github.com/supermorphic/homelab-playbook/issues/5)

Status: hybrid topology and architecture approved with review refinements below.
The guides describe operator procedures. The NUC #4 issuer, certificate handoff,
and modem route are not implemented by this design document.

## Decision and ownership

Use production ACME with Cloudflare DNS-01 and split certificate ownership:

| Consumer | Certificate owner | Browser connection |
| --- | --- | --- |
| UDM Network | Native UniFi OS issuer | Direct to UDM |
| Separate Protect endpoint | Its hosting console, after capability verification | Direct to Protect endpoint |
| UNAS Drive | Native UniFi OS issuer | Direct to UNAS |
| NUC #4 browser applications | Dedicated NUC #4 issuer | Through shared Caddy |
| ARRIS S34 Web Manager | NUC #4 issuer supplies Caddy's certificate | Caddy forwards over HTTPS to modem |

The operator selected this hybrid topology instead of distributing a wildcard
and private key to every appliance. The earlier proposal to place all appliance
interfaces behind Caddy is superseded. Protect remains a separate endpoint as
explicitly requested; do not infer its hosting console or OS version from the
UDM and UNAS reports.

Issue #25 owns Caddy's deployment model, private listener, routing schema,
service identity, and configuration reload. Issue #5 owns NUC #4 issuance,
renewal, certificate deployment, served-certificate verification, and the
modem-specific integration requirements. The operator's modem decision extends
the proxy use case to one explicitly configured remote private backend.

## Names and DNS

Use a single exact hostname and certificate for each UniFi console. The
[UniFi guide](../guides/unifi-tls.md) uses `udm.example.com`,
`protect.example.com`, and `nas.example.com` as placeholders. Pi-hole local
records point directly to those endpoints.

Use one separately issued `*.infra.example.com` wildcard for Caddy's directly
nested off-cluster hostnames, including `modem.infra.example.com`. Keep direct
UniFi names outside that namespace. The Caddy certificate's exact approved SAN
set is one DNS name: `*.infra.example.com`. Do not add `*.example.com`, the
namespace apex, UniFi names, or cluster names to that certificate.

Examples are synthetic; real names and addresses are operator inputs. The
dedicated namespace ensures the Caddy wildcard private key cannot authenticate
the directly managed UniFi names. This certificate boundary does not narrow the
Cloudflare token's separately documented zone-wide DNS permissions. A wildcard
covers neither its namespace apex nor deeper names such as
`service.extra.infra.example.com`. The cluster's certificate and issuer remain
independent; this design does not reuse their private keys, ACME accounts, or
DNS credentials. Expanding the approved SAN set requires an explicit design and
configuration review, not automatic inclusion of names requested by the issuer.

The modem name resolves to NUC #4's private listener. Caddy connects to the modem's
actual management address. All selected DNS names remain stable across private
address changes; update the relevant local records, backend addresses, and
routing instead of reissuing unchanged certificate names.

Public DNS serves ACME challenge records. Private browser names do not require
public address records, Cloudflare proxying, public ingress, or WAN port forwards.
Local DNS overrides must preserve public resolution of challenge records.

## NUC #4 issuance model

The proposed implementation uses a pinned lego binary, a dedicated non-login
host service account, and a systemd timer. Ansible manages installation,
configuration, permissions, and units. Pin an exact release and verified artifact
checksum for each supported architecture; never fetch a floating latest binary
at runtime. Use the repository's Debian 13 and Rocky Linux 9 baseline.

Alternatives considered:

- A rootless Podman issuer fits the established container foundation but adds
  cross-account file publication and host reload coordination for a short-lived
  client with no inbound listener.
- A host Certbot installation offers familiar renewal hooks but adds a Python
  client/plugin dependency set across both supported distributions.
- A host lego process keeps the client and Cloudflare provider in one pinned
  artifact and integrates directly with systemd. Select this for the initial
  implementation; do not make Caddy an ACME credential owner.

Use a persistent twice-daily timer with randomized delay and bounded execution.
Run renewal eligibility through the pinned client's supported behavior, with
ACME Renewal Information when available and a fallback threshold appropriate to
certificate lifetime. Do not hard-code an assumption that all certificates last
90 days. The implementation plan must bind these settings to the selected
client version and test its CLI contract.

Serialize all local issuance and deployment attempts. Do not force renewal on
every Ansible run. Retain client account state so ordinary provisioning and
renewal do not create a new account. Failed DNS validation leaves the previously
deployed certificate available and produces a failed operation with a bounded,
credential-free diagnostic.

## Credentials and privilege boundaries

Each UniFi console owns a separate zone-scoped Cloudflare token. The NUC #4
issuer gets another token, delivered from operator-managed SOPS inventory through
Ansible with secret logging and diff output disabled. No new live secret is
created, decrypted, or inspected by agents or CI.

Use DNS Edit and Zone Read restricted to the required Cloudflare zone. These
permissions apply across that zone; separate tokens enable independent rotation,
not record-level isolation. Do not grant a global API key or all-zone scope.
The UniFi guide distinguishes this proposed permission set from a verified
vendor minimum contract.

Keep the NUC token in a root-owned credential source, expose it only to the
issuer process through a private runtime credential file, and use file-based
provider credentials instead of command-line token arguments. Caddy, application
accounts, and CI workloads receive neither that token nor ACME account keys.
NUC #4 requires no live age identity merely to perform routine renewal.

Select one fixed privilege mechanism: an administrator-owned systemd timer starts
`homelab-tls-renew.service`, a root oneshot service whose fixed `ExecStart` is
`/usr/local/libexec/homelab-tls-reconcile`, with no command-line arguments. The
same root coordinator is used by the authorized Ansible renewal action. Its
executable, units, configuration, and parent directories are root-owned and not
writable by the issuer or proxy accounts.

The coordinator performs this sequence under one root-owned exclusive lock:

1. Load the fixed root-owned `/etc/homelab-tls/config.json` and validate its
   schema, ownership, paths, and exact approved SAN set. Reject command fields,
   executable hooks, unknown fields, and caller-supplied configuration paths.
2. Start and await the fixed `homelab-tls-issuer.service` system oneshot. Its
   administrator-owned unit runs the pinned client wrapper as the dedicated
   non-login `svc-acme` account with `NoNewPrivileges=yes`, no supplementary
   management groups, and only its private state writable. The issuer unit alone
   receives the Cloudflare runtime credential. Neither unit is a templated
   instance accepting caller-provided arguments.
3. Once the issuer unit has stopped, snapshot its bounded certificate/key files
   from fixed input locations into root-owned storage. Treat the bytes as
   untrusted data; do not execute output or consume issuer-supplied path,
   generation-name, command, environment, or argument metadata.
4. Validate, publish, force Caddy reload, verify the served certificate, and
   perform rollback when required. All these steps run in the root coordinator.
   It generates publication identifiers and destinations itself beneath the
   approved root. Caddy validation and reload use fixed argument vectors in a
   root-owned integration adapter installed for issue #25's selected runtime;
   they are never shell strings or issuer-controlled arguments.
5. Record issuance and publication results separately. A failed issuance does
   not prevent validation and retry of an already-issued pending certificate,
   but remains visible in the overall result. No valid pending candidate means
   leave the active generation unchanged.

The issuer cannot modify coordinator policy, publication paths, Caddy
configuration, reload commands, or verification targets. It has no sudo, polkit,
setuid-helper, systemd-management, or container-socket grant to invoke privileged
publication. It only produces certificate data; the independently privileged
coordinator owns the transition. Invoke subprocesses without a shell and with
an explicit sanitized environment. No inventory field is treated as a shell hook.

## Certificate handoff to Caddy

Keep three distinct state areas: issuer-private ACME state, administrator-owned
candidate snapshots, and published certificate generations readable by the
specific proxy identity. Publication never exposes the issuer's working directory
to Caddy. Directories are traversable only by required identities; private key
files are readable only by their owner and the proxy's specific read boundary.

Use a stable `current/fullchain.pem` and `current/privkey.pem` interface beneath
one administrator-owned certificate root. Publish both as a generation, then
atomically replace a relative `current` symlink to a complete generation beneath
that same root. Keep the parent root directory itself stable; do not replace it
during publication or rollback. The implementation must
bind the root path and proxy read access to issue #25's actual runtime contract.
Do not install guessed service names, UID allocations, or reload commands while
that implementation is absent from this checkout.

If issue #25 selects containerized Caddy, bind-mount the stable parent certificate
root read-only into the container. Do not mount `current`, its resolved generation
directory, or individual certificate files. For example, mounting the host
publication root at `/etc/caddy/certificates` lets Caddy read
`/etc/caddy/certificates/current/fullchain.pem` and
`/etc/caddy/certificates/current/privkey.pem`. Relative symlink targets must remain
within that mounted root. Each switch and rollback is therefore visible on the
next file open in the existing container; force reload to reopen the files
without recreating the container. Ensure new generations have the required
numeric ownership, read permissions, and SELinux labels before switching, not
only when the mount is first created. The mount contains only published
generations, never issuer state, credential sources, or candidate snapshots.

Before publication, copy bounded regular-file inputs into an administrator-owned
snapshot without following untrusted symlinks. Validate only that immutable
snapshot: key matches leaf certificate, exact approved SAN set, server use,
current validity and usable remaining lifetime, and chain verification against
the host's public trust store. Compare canonical DNS SAN values against the
root-owned approved set for equality, not subset coverage. Reject missing,
duplicate, or additional SANs and any unapproved SAN type, including IP addresses
or URIs. A certificate with the required wildcard plus any other name fails.
Never use Common Name as a substitute for SAN validation. Reject staging
certificates from production publication. Never trust issuer-provided metadata
alone as the validation oracle.

Repeat ownership, target-path, and active-generation checks immediately before
switching. Validate Caddy configuration with the candidate generation before
activation. After activation, force Caddy to reload certificate files even when
its configuration text is unchanged, using the issue #25 reload interface.
Retain the previous generation until activation is verified.

Verify a fresh TLS handshake against the intended private listener with the
configured hostname as SNI: public chain, hostname, validity, and exact deployed
leaf fingerprint must match. Check each declared hostname; a successful reload
exit code or a valid certificate on disk is insufficient.

On reload or certificate-verification failure, restore the previous generation,
reload it, and verify restoration. Preserve both the original failure and any
restoration failure. If no prior generation exists, leave the unverified route
inactive and report the incomplete first deployment.

Reconcile pending publication on subsequent timer runs even when no new
certificate is issued. Issuance and deployment outcomes remain separate: a
deployment retry must not force another ACME order. Do not roll back a correct
certificate solely because an application backend is unavailable; report backend
health separately from certificate activation.

## Modem integration

The [modem guide](../guides/modem-proxy.md) defines the selected S34 route.
Use a route-specific trust pool and certificate name for its HTTPS backend after
the operator establishes the modem certificate's identity. Preserve hostname,
chain, and validity checks. Do not assume a captured self-signed certificate has
usable SANs or remains stable across firmware updates.

If authenticated backend TLS cannot be established, keep the modem route inactive
and preserve direct modem access while the operator resolves that boundary.
There is no automatic fallback to disabled verification or HTTP. Route-specific
redirect or cookie handling is added only after observed compatibility tests
demonstrate a need. The proxy receives no stored modem login credential.

Acceptance covers login/logout, status navigation, redirects, backend trust, and
preservation of unrelated routes. It does not reboot or reset the modem. Pi-hole
and Caddy must remain optional for direct modem recovery access.

## Operator interface and validation

Propose `tls provision`, `tls renew`, and `tls verify` through the canonical
`mise run playbook -- <playbook> <action> <inventory> [ansible-args...]` gateway.
These are proposed interfaces, not currently available commands.

- `provision` installs and reconciles local capability and declared configuration.
  Enabling its timer grants ongoing issuance/deployment intent and must be
  explicit in the operator's target authorization and configuration.
- `renew` runs one bounded renewal/deployment reconciliation, including retries
  for an already-issued pending certificate. It can mutate DNS and certificate
  state and is not an observational check.
- `verify` observes units, permissions, certificate state, and configured TLS
  endpoints. It neither requests certificates nor reloads services.

Extend guarded host-action validation to this family. Production and staging
playbook execution remains separately authorized for the exact target, action,
and arguments. Normal operation uses the production issuer. An explicitly
selected ACME staging experiment uses separate account/state/output directories
and cannot publish into the production certificate root or listener.

Offline tests use synthetic names and ephemeral local keys. They cover malformed
inputs, permissions, concurrent attempts, certificate/key mismatch, missing or
additional SANs, unapproved SAN types, expired or untrusted chains, publication
failure, forced reload, rollback, interrupted deployment retry without reissuance,
and observational verification. Include a validly signed certificate containing
the approved wildcard plus a UniFi hostname and prove that publication rejects
it. Prove the published wildcard does not authenticate direct UniFi names.

Privilege tests attempt issuer-controlled destination paths, symlinks, command
metadata, and arguments. Verify that the issuer cannot write coordinator policy
or published generations and that no such input changes the fixed privileged
operation. Exercise pending publication retry after issuance failure.

For containerized Caddy, a bounded registered container test mounts the stable
parent once, publishes a replacement generation, forces reload, and checks the
new served fingerprint without container recreation. Roll back and check the
previous fingerprint in the same container. Assert the container identity is
unchanged and include the supported platform's file-label and permission checks.
Use independent cryptographic checks and effective system state as oracles.
Bounded local TLS servers prove served-certificate checks; no Cloudflare token,
production ACME request, or inventory host is available to CI.

Run the required depth selected by `mise run ci:changed`; role and unit changes
must also prove Debian/Rocky behavior through the registered disposable tests.
Synthetic tests do not prove live issuance, UniFi automatic renewal, modem UI
compatibility, or physical host recovery.

## Recovery and outstanding operator evidence

Keep GitHub-hosted automation, administrative SSH/console access, Cloudflare
account recovery, and encrypted backups available without NUC #4 or Kubernetes.
Retain ACME account state and valid deployed generations in independent encrypted
backups; protect their keys as secrets. A rebuilt host must allow administrative
access and baseline provisioning before any TLS automation or Caddy starts.

Restore certificate state when available to avoid unnecessary issuance during
recovery. If state is unavailable, reissue only after restoring independent DNS,
time, outbound access, and credential access, accounting for CA rate limits.
UniFi consoles follow their separate native recovery procedures.

Required live evidence includes UniFi issuance and a later automatic renewal,
the separate Protect console's capability, NUC timer renewal and recovery, and
the modem's backend trust and browser workflow. None is claimed by this spec.
Technitium remains an issue #5 consumer whose hosting location and required
protocols have not been supplied; do not invent a target or deploy certificate
files to it. Resolve that consumer before closing the full issue.

## References

- [Podman foundation design](006-podman-quadlet-foundation.md)
- [SOPS credential boundary](005-sops-age-secrets.md)
- [Command lifecycle](../reference/repository-command-lifecycle.md)
- [Shared proxy issue #25](https://github.com/supermorphic/homelab-playbook/issues/25)
- [lego certificate operations](https://go-acme.github.io/lego/obtain/)
- [lego Cloudflare provider](https://go-acme.github.io/lego/dns/cloudflare/)
- [Caddy reload behavior](https://caddyserver.com/docs/command-line#caddy-reload)
- [Caddy HTTPS transport](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#the-http-transport)
- [Podman Quadlet volume configuration](https://docs.podman.io/en/stable/markdown/podman-systemd.unit.5.html)
