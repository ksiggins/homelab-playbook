# ARRIS S34 browser access through Caddy

The selected [hybrid TLS design](../specs/007-off-cluster-tls-trust.md) includes
private HTTPS access to the S34 through the shared Caddy proxy on NUC #4.
The proxy and certificate deployment are not implemented in this checkout yet.
Use this guide as the configuration and acceptance procedure when those
components become available; it does not claim an operational route.

ARRIS documents its local Web Manager and browser certificate warnings, but
provides no certificate upload or automated renewal procedure in those guides.
The modem retains its existing HTTPS configuration. Caddy presents the separately
managed public certificate to browsers and opens an independent HTTPS connection
to the modem.

## DNS and routing

These values are synthetic examples, not production inputs:

| Input | Example | Meaning |
| --- | --- | --- |
| Browser hostname | `modem.infra.example.com` | Covered by Caddy's `*.infra.example.com` certificate |
| Pi-hole local A record | `modem.infra.example.com` to `192.0.2.40` | NUC #4's private proxy listener address |
| HTTPS backend | `https://192.0.2.50:443` | Modem's actual management address |

Keep Caddy-served names under `infra.example.com`, separate from direct UniFi
names such as `udm.example.com`, `protect.example.com`, and `nas.example.com`.
Caddy's certificate contains exactly the `*.infra.example.com` DNS SAN; it does
not include a broader wildcard or the directly managed appliance names.

Create the exact local record on each Pi-hole instance used by management
clients. The browser name resolves to NUC #4, not the modem. The Caddy backend
must resolve or connect directly to the modem, not back to its own listener.
Verify NUC #4 has a route to the modem management network and restrict proxy
ingress to the intended private management networks. No public listener or
WAN port forwarding is needed.

Add a single explicit hostname route through the proxy's Ansible-managed
configuration. Issue #25 owns the proxy runtime, configuration validation, and
reload interface; issue #5 supplies the certificate and the modem integration
requirements. Preserve the shared proxy's healthy routes when adding this one.

When the modem's address changes, update the backend and any affected routing
rules. The browser hostname and certificate can remain unchanged. When NUC #4's
listener address changes, update the Pi-hole record instead.

## Establish backend TLS trust

Before enabling the route, inspect the modem's public certificate from a trusted
management connection. Record its issuer, validity, subject alternative names,
and fingerprint in private operator records. Confirm its identity through an
independent trusted observation before installing it as a trust anchor; merely
capturing a certificate from an unknown endpoint is not sufficient.

Configure trust specifically for the modem route, using Caddy's file-based TLS
trust pool and a server name that matches a certificate subject alternative
name. A private trust anchor does not bypass certificate expiry or hostname
validation. If the modem has no usable certificate name, or its certificate
cannot pass validation, stop route activation and retain direct modem access.

Do not silently fall back to HTTP, disable TLS verification, alter the system
trust store, or rewrite firmware. An exception to backend authentication is a
separate operator decision and is not part of the selected configuration.
After a modem replacement or firmware change that replaces its certificate,
repeat trust establishment before updating the route's trust material.

Keep appliance certificate material outside public repository artifacts when it
contains infrastructure identifiers. Supply any protected repository input under
the existing SOPS boundary. The proxy never receives a modem administrator
password merely to forward browser requests.

## Acceptance procedure

After the operator authorizes deployment of the exact proxy configuration:

1. Validate the candidate Caddy configuration before reload. A failed candidate
   must leave the currently working configuration available.
2. Resolve the browser hostname from a client using Pi-hole. Confirm it points
   to NUC #4's intended private listener.
3. Open the HTTPS hostname and confirm the browser receives a publicly trusted
   certificate covering it, with the expected deployed certificate fingerprint.
4. Test login, logout, status pages, and event-log navigation. Confirm redirects
   remain usable through the hostname and do not produce certificate warnings.
5. Confirm backend certificate validation remains enabled and successful.
6. Confirm unrelated proxy routes still work.

These checks do not require a modem reboot, factory reset, firmware change, or
Internet service interruption. Do not use those actions as acceptance tests.
If redirects, cookies, or application behavior require special handling, inspect
the actual failure and add only a tested route-specific change. A trusted
browser certificate alone does not prove the entire Web Manager works.

## Recovery

Keep a direct modem management bookmark and the documented local access method
available independently of Pi-hole, NUC #4, Caddy, and Internet connectivity.
Proxy access is a convenience and must not be required to restore connectivity.
The direct IP URL may retain the modem's existing certificate warning.

If backend trust or application compatibility fails, disable only the modem
route and preserve other proxy services. Restore that route only after its
specific acceptance checks pass. An offline NUC #4 interrupts proxied browser
access, not the modem's forwarding function.

## References

- [ARRIS S33/S34 Web Manager access](https://arris.my.salesforce-sites.com/consumers/articles/knowledge/S33-Web-Manager-Access)
- [ARRIS certificate-warning guidance](https://arris.my.salesforce-sites.com/consumers/articles/knowledge/Alert-Message-for-Web-Manager-Access)
- [Caddy HTTPS backend transport](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#the-http-transport)
