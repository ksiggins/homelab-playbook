#!/usr/bin/python3
"""Report a bounded, synthetic-only reverse proxy activation stage failure."""

import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys


HELPER = Path("/usr/local/libexec/homelab-reverse-proxy")


def load_helper():
    loader = importlib.machinery.SourceFileLoader("homelab_reverse_proxy", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None or spec.loader is None:
        raise RuntimeError("activation helper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def adapted_summary(configuration):
    tls = configuration.get("apps", {}).get("tls", {})
    loads = tls.get("certificates", {}).get("load_files", [])
    servers = configuration.get("apps", {}).get("http", {}).get("servers", {})
    return {
        "loads": [
            {"keys": sorted(pair), "tags": pair.get("tags", [])} for pair in loads
        ],
        "servers": [
            {
                "automatic_https": server.get("automatic_https", {}),
                "listen": server.get("listen", []),
                "policies": server.get("tls_connection_policies", []),
                "protocols": server.get("protocols", []),
            }
            for server in servers.values()
        ],
    }


def difference_paths(expected, actual, path="$", limit=20):
    if expected == actual or limit <= 0:
        return []
    if type(expected) is not type(actual):
        return [f"{path}:type"]
    if isinstance(expected, dict):
        result = []
        for key in sorted(set(expected) | set(actual)):
            child = f"{path}.{key}"
            if key not in expected:
                result.append(f"{child}:extra")
            elif key not in actual:
                result.append(f"{child}:missing")
            else:
                result.extend(
                    difference_paths(
                        expected[key], actual[key], child, limit - len(result)
                    )
                )
            if len(result) >= limit:
                break
        return result[:limit]
    if isinstance(expected, list):
        expected_items = sorted(json.dumps(item, sort_keys=True) for item in expected)
        actual_items = sorted(json.dumps(item, sort_keys=True) for item in actual)
        if expected_items == actual_items:
            return [f"{path}:list-order"]
        if len(expected) != len(actual):
            return [f"{path}:length"]
        result = []
        for index, (expected_item, actual_item) in enumerate(zip(expected, actual)):
            result.extend(
                difference_paths(
                    expected_item,
                    actual_item,
                    f"{path}[{index}]",
                    limit - len(result),
                )
            )
            if len(result) >= limit:
                break
        return result[:limit]
    return [f"{path}:value"]


def runtime_summary(activator, desired):
    activator.active()
    activator.socket_metadata()
    active = activator.commands.configuration(activator.socket)
    pid = activator.commands.run(
        [
            "/usr/bin/systemctl",
            "show",
            "--property=MainPID",
            "--value",
            "caddy.service",
        ]
    ).decode().strip()
    socket_rows = activator.commands.run(["ss", "-H", "-lnptu"]).decode().splitlines()
    process_rows = [row for row in socket_rows if f"pid={pid}," in row]
    tcp_443_rows = []
    for row in socket_rows:
        fields = row.split()
        if len(fields) >= 5 and fields[0] == "tcp" and fields[4].endswith(":443"):
            tcp_443_rows.append(row)
    try:
        caddy_fd_count = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        caddy_fd_accessible = True
    except OSError:
        caddy_fd_count = 0
        caddy_fd_accessible = False
    capability = next(
        (
            line.partition(":")[2].strip()
            for line in Path("/proc/self/status").read_text().splitlines()
            if line.startswith("CapEff:")
        ),
        "unavailable",
    )
    return {
        "caddy_fd_accessible": caddy_fd_accessible,
        "caddy_fd_count": caddy_fd_count,
        "effective_capabilities": capability,
        "configuration_differences": difference_paths(desired, active),
        "expected_listeners": sorted(activator.expected_listeners(desired)),
        "main_pid_is_numeric": pid.isdigit() and int(pid) > 0,
        "process_listener_rows": process_rows[:10],
        "tcp_443_rows": tcp_443_rows[:10],
    }


def main():
    runtime = sys.argv[1:] == ["runtime"]
    if sys.argv[1:] not in ([], ["runtime"]):
        print("usage: diagnose.py [runtime]")
        return 2
    try:
        helper = load_helper()
        activator = helper.Activator()
        activator.preflight()
        if not activator.candidate.exists():
            try:
                activator.manifest().candidate()
            except Exception as error:
                print(json.dumps({"stage": "desired-manifest",
                                  "error_type": type(error).__name__}, sort_keys=True))
                return 1
        adapted = activator.adapted(activator.candidate)
        activator.certificates(adapted)
        activator.caddy("validate", activator.candidate)
        report = {"adapted": adapted_summary(adapted), "result": "static-valid"}
        if runtime:
            try:
                activator.caddy("reload", activator.candidate)
                report["runtime"] = runtime_summary(activator, adapted)
                try:
                    activator.served_tls(adapted)
                except helper.ActivationError as error:
                    report["served_tls_error"] = str(error)
            finally:
                activator.caddy("reload", activator.boot)
    except Exception as error:  # Diagnostics must survive any native boundary.
        message = (
            str(error)
            if error.__class__.__name__ == "ActivationError"
            else "diagnostic stage could not complete"
        )
        print(json.dumps({"error": message}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
