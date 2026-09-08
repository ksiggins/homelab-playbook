"""Controller-safe parser for one fixed systemd execution command."""


def exec_start_matches(value, expected):
    if (not isinstance(value, str) or not value.startswith("{ ")
            or not value.endswith(" }")):
        return False
    fields = {}
    for item in value[2:-2].split(" ; "):
        key, separator, field_value = item.partition("=")
        if not separator or not key or key in fields:
            return False
        fields[key] = field_value
    stable = {
        "path": expected,
        "argv[]": expected,
        "ignore_errors": "no",
    }
    transient = {"start_time", "stop_time", "pid", "code", "status"}
    return (
        all(
            fields.get(key) == expected_value
            for key, expected_value in stable.items()
        )
        and not (set(fields) - set(stable) - transient)
    )



SERVICE_ARRAY_PROPERTIES = ("ExecCondition", "ExecStartPre", "ExecStartPost", "LoadCredential")
_SERVICE_PATHS = {
    "homelab-tls-issuer.service": "/org/freedesktop/systemd1/unit/homelab_2dtls_2dissuer_2eservice",
    "homelab-tls-renew.service": "/org/freedesktop/systemd1/unit/homelab_2dtls_2drenew_2eservice",
}


def service_array_query(unit):
    """Return the fixed typed property query for one supported service."""
    if unit not in _SERVICE_PATHS:
        raise ValueError("unsupported TLS service property target")
    return ["/usr/bin/busctl", "--system", "--timeout=15s", "get-property",
            "org.freedesktop.systemd1", _SERVICE_PATHS[unit],
            "org.freedesktop.systemd1.Service", *SERVICE_ARRAY_PROPERTIES]


def merge_service_arrays(properties, unit, typed_output):
    """Fill special arrays only from exact successful D-Bus property evidence.

    systemctl v252/v257 omit empty Exec arrays, and LoadCredential's a(ss)
    value has no systemctl printer. busctl preserves each type and array count.
    No missing property, unknown type, or nonempty auxiliary command is accepted.
    """
    service_array_query(unit)
    if isinstance(typed_output, bytes):
        typed_output = typed_output.decode("ascii")
    credential = "cloudflare-token:/etc/homelab-tls/cloudflare-token" if unit == "homelab-tls-issuer.service" else ""
    credential_array = ('a(ss) 1 "cloudflare-token" "/etc/homelab-tls/cloudflare-token"'
                        if credential else "a(ss) 0")
    if (not isinstance(typed_output, str)
            or typed_output.splitlines() != ["a(sasbttttuii) 0"] * 3 + [credential_array]):
        raise ValueError("unexpected typed TLS service arrays")
    expected = {"ExecCondition": "", "ExecStartPre": "", "ExecStartPost": "", "LoadCredential": credential}
    result = dict(properties)
    for key, value in expected.items():
        if key in result and result[key] != value:
            raise ValueError("conflicting TLS service array properties")
        result[key] = value
    return result
