# Shared private reverse proxy

These playbooks manage distribution-packaged Caddy as a host systemd service on
Debian 13 and Rocky Linux 9. They target `reverse_proxy_hosts` through the
canonical `mise run playbook` gateway. The existing OS baseline is a prerequisite.

- `provision.yml` installs the package and managed service configuration,
  reconciles the shared private firewall policy, activates declared routes, and
  verifies effective state.
- `verify.yml` observes the installed service, configuration, certificate
  consumption, and firewall state. It does not repair state or create test routes.

Both actions require the existing key-only `ansible` account and passwordless
sudo. Production and staging execution require separate explicit authorization
for the exact action, inventory, and arguments. Adding inventory membership or
passing `--check` does not supply that authorization.

## Inputs and ownership

`reverse_proxy_bind_addresses`, `reverse_proxy_client_sources`, and
`reverse_proxy_routes` default to empty lists. With no routes, Caddy has only a
permission-protected Unix admin socket; no HTTPS listener or allowance exists.
Active routes require explicit private bind addresses and client CIDRs. HTTPS
client sources are independent of the SSH management-source list.

Each route has an exact `hostname`, a `backend_port` from 1024 through 65535,
and a safe `certificate_name`. Caddy always connects to
`127.0.0.1:<backend_port>`. Application roles own port allocation and loopback-only
publication under their separate Podman accounts. No socket-based discovery or
application account membership is required by Caddy.

The complete desired route list is authoritative. Removing a route removes new
requests to that backend; removing the final route removes HTTPS listeners and
firewall allowances. It does not delete application data or external certificates.

The `caddy` account reads root-owned configuration and externally deployed TLS
files. The certificate owner supplies
`/etc/caddy/tls/<certificate_name>/current/fullchain.pem` and `privkey.pem`
through an atomic version-directory pointer. Certificate generation, renewal,
and issuer credentials belong to issue #5.

## Update and recovery boundaries

Install Caddy with `state: present` from Debian's distribution repository or
EPEL on Rocky. Do not pin its version, hold the package, or run `caddy upgrade`.
Existing OS maintenance upgrades packages. Binary upgrades may restart Caddy
and briefly interrupt every route; configuration rollback is not package rollback.

Configuration changes validate under the service identity before reload and
preserve the committed boot configuration on failure. A root-owned transaction
record permits interrupted configuration recovery before systemd starts Caddy.
Successful reloads can close WebSockets; applications must reconnect. The Debian
package does not support the newer WebSocket drain-delay option.

See the [operator guide](../../docs/guides/reverse-proxy.md) for deployment,
certificate handoff, verification, and recovery. [Specification 007](../../docs/specs/007-shared-private-reverse-proxy.md)
records the deployment comparison and acceptance requirements. Offline tests
use disposable certificate and backend fixtures; production network reachability,
physical boot, and certificate issuance remain separate operator evidence.
