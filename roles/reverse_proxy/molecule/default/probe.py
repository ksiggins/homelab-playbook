#!/usr/bin/env python3
"""Make verified HTTPS and WebSocket requests without third-party modules."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path


def _read_exact(stream, length: int) -> bytes:
    value = stream.read(length)
    if len(value) != length:
        raise ConnectionError("incomplete response")
    return value


def _connect(arguments: argparse.Namespace):
    context = ssl.create_default_context(cafile=arguments.ca_file)
    plain = socket.create_connection((arguments.address, arguments.port), timeout=5)
    return context.wrap_socket(plain, server_hostname=arguments.hostname)


def _certificate_hash(connection: ssl.SSLSocket) -> str:
    certificate = connection.getpeercert(binary_form=True)
    if certificate is None:
        raise ssl.SSLError("peer did not provide a certificate")
    return hashlib.sha256(certificate).hexdigest()


def _https(arguments: argparse.Namespace) -> dict[str, object]:
    with _connect(arguments) as connection:
        certificate_sha256 = _certificate_hash(connection)
        host = arguments.host or arguments.hostname
        connection.sendall(
            (
                f"GET {arguments.path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        )
        response = http.client.HTTPResponse(connection)
        response.begin()
        body = response.read().decode("utf-8")
        return {
            "body": body,
            "certificate_sha256": certificate_sha256,
            "status": response.status,
        }


def _write_websocket_frame(connection: ssl.SSLSocket, payload: bytes) -> None:
    mask = os.urandom(4)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    if len(payload) < 126:
        header = bytes((0x81, 0x80 | len(payload)))
    elif len(payload) <= 0xFFFF:
        header = bytes((0x81, 0x80 | 126)) + struct.pack("!H", len(payload))
    else:
        header = bytes((0x81, 0x80 | 127)) + struct.pack("!Q", len(payload))
    connection.sendall(header + mask + masked)


def _read_websocket_frame(stream) -> bytes:
    first, second = _read_exact(stream, 2)
    if first & 0x0F != 1 or second & 0x80:
        raise ConnectionError("unexpected WebSocket response frame")
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _read_exact(stream, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _read_exact(stream, 8))[0]
    return _read_exact(stream, length)


def _websocket_connect(arguments: argparse.Namespace):
    connection = _connect(arguments)
    certificate_sha256 = _certificate_hash(connection)
    websocket_key = base64.b64encode(os.urandom(16)).decode("ascii")
    host = arguments.host or arguments.hostname
    connection.sendall(
        (
            f"GET {arguments.path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {websocket_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
    )
    response = http.client.HTTPResponse(connection)
    response.begin()
    if response.status != 101:
        connection.close()
        raise ConnectionError(f"WebSocket upgrade returned {response.status}")
    return connection, connection.makefile("rb"), certificate_sha256


def _exchange(connection: ssl.SSLSocket, stream, message: str) -> str:
    _write_websocket_frame(connection, message.encode("utf-8"))
    return _read_websocket_frame(stream).decode("utf-8")


def _websocket(arguments: argparse.Namespace) -> dict[str, object]:
    connection, stream, certificate_sha256 = _websocket_connect(arguments)
    with connection, stream:
        reply = _exchange(connection, stream, arguments.message)
    return {
        "certificate_sha256": certificate_sha256,
        "message": reply,
        "status": 101,
    }


def _session(arguments: argparse.Namespace) -> dict[str, object]:
    ready_file = Path(arguments.ready_file)
    continue_file = Path(arguments.continue_file)
    connection, stream, certificate_sha256 = _websocket_connect(arguments)
    with connection, stream:
        _exchange(connection, stream, "before-signal")
        ready_file.touch(mode=0o600, exist_ok=False)
        deadline = time.monotonic() + arguments.wait_seconds
        while not continue_file.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out waiting for continuation signal")
            time.sleep(0.05)
        try:
            message = _exchange(connection, stream, "after-signal")
            preserved = True
        except (ConnectionError, OSError, ssl.SSLError):
            preserved = False
            replacement, replacement_stream, _ = _websocket_connect(arguments)
            with replacement, replacement_stream:
                message = _exchange(
                    replacement, replacement_stream, "after-signal"
                )
    return {
        "certificate_sha256": certificate_sha256,
        "connection_preserved": preserved,
        "message": message,
        "status": 101,
    }


def parse_ss_listeners(output: str) -> list[dict[str, str]]:
    """Extract the protocol and local-address columns from ``ss -H -lnut``."""
    listeners = []
    for row in output.splitlines():
        columns = row.split()
        if len(columns) >= 6 and columns[0] in {"tcp", "udp"}:
            listeners.append({"protocol": columns[0], "local": columns[4]})
    return listeners


def classify_listeners(
    listeners: list[dict[str, str]], expected_address: str
) -> dict[str, list[str]]:
    """Return required and forbidden port listeners from parsed ``ss`` rows."""
    ipaddress.ip_address(expected_address)
    result = {"tcp_443": [], "tcp_80": [], "udp_443": []}
    for listener in listeners:
        endpoint = listener["local"]
        port = endpoint.rpartition(":")[2]
        if listener["protocol"] == "tcp" and port == "443":
            result["tcp_443"].append(endpoint)
        elif listener["protocol"] == "tcp" and port == "80":
            result["tcp_80"].append(endpoint)
        elif listener["protocol"] == "udp" and port == "443":
            result["udp_443"].append(endpoint)
    result["tcp_443"].sort()
    result["tcp_80"].sort()
    result["udp_443"].sort()
    return result


def _listeners(expected_address: str) -> dict[str, list[str]]:
    executable = shutil.which("ss", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if executable is None:
        raise FileNotFoundError("ss is unavailable in trusted system paths")
    result = subprocess.run(
        [executable, "-H", "-lnut"],
        check=True,
        capture_output=True,
        text=True,
    )
    return classify_listeners(parse_ss_listeners(result.stdout), expected_address)


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--host")
    parser.add_argument("--ca-file", required=True)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    https = subparsers.add_parser("https")
    https.add_argument("--path", default="/")
    websocket = subparsers.add_parser("websocket")
    websocket.add_argument("--path", default="/")
    websocket.add_argument("--message", required=True)
    session = subparsers.add_parser("session")
    session.add_argument("--path", default="/")
    session.add_argument("--ready-file", required=True)
    session.add_argument("--continue-file", required=True)
    session.add_argument("--wait-seconds", type=float, default=30)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    if len(raw_arguments) == 2 and raw_arguments[0] == "listeners":
        print(json.dumps(_listeners(raw_arguments[1]), sort_keys=True))
        return 0
    arguments = parse_arguments(raw_arguments)
    operations = {
        "https": _https,
        "session": _session,
        "websocket": _websocket,
    }
    result = operations[arguments.operation](arguments)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
