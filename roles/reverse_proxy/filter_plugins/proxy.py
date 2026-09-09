"""Strict, deterministic inputs for the repository-owned reverse proxy."""

import ipaddress
import re
from collections.abc import Mapping

_PRIVATE = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_CERTIFICATE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


def _private(value, network):
    if not isinstance(value, str) or "%" in value or (network and "/" not in value):
        raise ValueError("proxy addresses must be explicit private addresses or CIDRs")
    try:
        address = ipaddress.ip_network(value, strict=True) if network else ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("proxy address or CIDR is invalid") from None
    if not any(address.version == allowed.version and (
        address.subnet_of(allowed) if network else address in allowed
    ) for allowed in _PRIVATE):
        raise ValueError("proxy ingress must use RFC1918 or ULA addresses")
    return str(address)


def validate(value):
    """Return canonical fields without accepting arbitrary template fragments."""
    fields = {"bind_addresses", "client_sources", "routes"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("proxy configuration requires only bind_addresses, client_sources and routes")
    if any(not isinstance(value[field], list) for field in fields):
        raise ValueError("proxy configuration fields must be lists")
    result = {"bind_addresses": sorted(set(_private(item, False) for item in value["bind_addresses"])),
              "client_sources": sorted(set(_private(item, True) for item in value["client_sources"])),
              "routes": []}
    if value["routes"] and (not result["bind_addresses"] or not result["client_sources"]):
        raise ValueError("configured proxy routes require bind addresses and client sources")
    hostnames = set()
    for route in value["routes"]:
        if not isinstance(route, Mapping) or set(route) != {"hostname", "backend_port", "certificate_name"}:
            raise ValueError("proxy route requires only hostname, backend_port and certificate_name")
        hostname = route["hostname"]
        if (not isinstance(hostname, str) or len(hostname) > 253 or "." not in hostname
                or any(not _LABEL.fullmatch(label) for label in hostname.lower().split("."))):
            raise ValueError("proxy hostname must be an exact DNS hostname")
        hostname = hostname.lower()
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("proxy hostname must be a DNS name, not an IP literal")
        if hostname in hostnames:
            raise ValueError("proxy hostname is declared more than once")
        hostnames.add(hostname)
        port = route["backend_port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError("proxy backend port must be an integer from 1024 through 65535")
        certificate = route["certificate_name"]
        if not isinstance(certificate, str) or not _CERTIFICATE.fullmatch(certificate):
            raise ValueError("proxy certificate name must be a restricted filesystem component")
        result["routes"].append({"hostname": hostname, "backend_port": port, "certificate_name": certificate})
    result["routes"].sort(key=lambda route: route["hostname"])
    return result


class FilterModule:
    def filters(self):
        return {"reverse_proxy_validate": validate}
