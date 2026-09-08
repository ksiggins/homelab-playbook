from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_DIRECTORY = (
    REPOSITORY_ROOT / "roles" / "reverse_proxy" / "molecule" / "default"
)
BACKEND_PATH = SCENARIO_DIRECTORY / "backend.py"
PROBE_PATH = SCENARIO_DIRECTORY / "probe.py"
DIAGNOSE_PATH = SCENARIO_DIRECTORY / "diagnose.py"


def load_backend():
    spec = importlib.util.spec_from_file_location("reverse_proxy_backend", BACKEND_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {BACKEND_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_probe():
    spec = importlib.util.spec_from_file_location("reverse_proxy_probe", PROBE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {PROBE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_diagnose():
    spec = importlib.util.spec_from_file_location(
        "reverse_proxy_diagnose", DIAGNOSE_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {DIAGNOSE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FixtureProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backend = load_backend()
        cls.diagnose = load_diagnose()
        cls.probe = load_probe()

    def test_diagnostic_loads_extensionless_activation_helper(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            helper = Path(directory_name) / "homelab-reverse-proxy"
            helper.write_text("fixture_value = 42\n", encoding="utf-8")
            original = self.diagnose.HELPER
            self.diagnose.HELPER = helper
            self.addCleanup(setattr, self.diagnose, "HELPER", original)

            loaded = self.diagnose.load_helper()

        self.assertEqual(42, loaded.fixture_value)

    def test_diagnostic_reports_only_paths_for_reordered_configuration(self) -> None:
        expected = {"apps": {"policies": [{"sni": "app"}, {"sni": "other"}]}}
        actual = {"apps": {"policies": [{"sni": "other"}, {"sni": "app"}]}}

        differences = self.diagnose.difference_paths(expected, actual)

        self.assertEqual(["$.apps.policies:list-order"], differences)

    def test_listener_parser_uses_protocol_and_local_address_columns(self) -> None:
        output = (
            "tcp LISTEN 0 4096 10.88.0.10:443 0.0.0.0:*\n"
            "tcp LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*\n"
            "udp UNCONN 0 0 *:443 0.0.0.0:*\n"
        )

        listeners = self.probe.parse_ss_listeners(output)
        self.assertEqual(
            [
                {"local": "10.88.0.10:443", "protocol": "tcp"},
                {"local": "0.0.0.0:80", "protocol": "tcp"},
                {"local": "*:443", "protocol": "udp"},
            ],
            listeners,
        )
        self.assertEqual(
            {
                "tcp_443": ["10.88.0.10:443"],
                "tcp_80": ["0.0.0.0:80"],
                "udp_443": ["*:443"],
            },
            self.probe.classify_listeners(listeners, "10.88.0.10"),
        )

    def test_listener_probe_resolves_ss_from_trusted_distro_paths(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="tcp LISTEN 0 4096 10.0.0.2:443 0.0.0.0:*\n"
        )
        with (
            mock.patch.object(
                self.probe.shutil, "which", return_value="/usr/sbin/ss"
            ) as which,
            mock.patch.object(
                self.probe.subprocess, "run", return_value=completed
            ) as run,
        ):
            listeners = self.probe._listeners("10.0.0.2")

        which.assert_called_once_with(
            "ss", path="/usr/sbin:/usr/bin:/sbin:/bin"
        )
        run.assert_called_once_with(
            ["/usr/sbin/ss", "-H", "-lnut"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(["10.0.0.2:443"], listeners["tcp_443"])

    def start_server(self, context: ssl.SSLContext | None = None):
        server = self.backend.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.backend.FixtureHandler
        )
        if context is not None:
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def test_backend_returns_exact_host_and_path_body(self) -> None:
        server = self.start_server()
        with socket.create_connection(server.server_address, timeout=2) as connection:
            connection.sendall(
                b"GET /ready HTTP/1.1\r\n"
                b"Host: app.example.test\r\n"
                b"Connection: close\r\n\r\n"
            )
            response = b""
            while chunk := connection.recv(4096):
                response += chunk

        self.assertIn(b"HTTP/1.0 200 OK\r\n", response)
        self.assertTrue(
            response.endswith(b"fixture host=app.example.test path=/ready\n"),
            response,
        )

    def test_backend_identifies_an_unknown_host_if_proxy_routing_reaches_it(self) -> None:
        server = self.start_server()
        with socket.create_connection(server.server_address, timeout=2) as connection:
            connection.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: unknown.example.test\r\n"
                b"Connection: close\r\n\r\n"
            )
            response = b""
            while chunk := connection.recv(4096):
                response += chunk

        self.assertTrue(
            response.endswith(b"fixture host=unknown.example.test path=/\n"),
            response,
        )

    def test_backend_echoes_one_masked_websocket_text_frame(self) -> None:
        server = self.start_server()
        websocket_key = base64.b64encode(b"0123456789abcdef").decode("ascii")
        with socket.create_connection(server.server_address, timeout=2) as connection:
            connection.sendall(
                (
                    "GET /socket HTTP/1.1\r\n"
                    "Host: app.example.test\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {websocket_key}\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode("ascii")
            )
            headers = b""
            while b"\r\n\r\n" not in headers:
                headers += connection.recv(4096)
            self.assertIn(b"101 Switching Protocols", headers)

            for message in (b"round-trip", b"still-open"):
                mask = b"\x01\x02\x03\x04"
                masked = bytes(
                    value ^ mask[index % 4] for index, value in enumerate(message)
                )
                connection.sendall(
                    bytes((0x81, 0x80 | len(message))) + mask + masked
                )
                header = connection.recv(2)
                length = header[1] & 0x7F
                reply = connection.recv(length)
                self.assertEqual(bytes((0x81, len(message))), header)
                self.assertEqual(message, reply)

    def test_probe_verifies_tls_hostname_body_and_websocket(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key = directory / "key.pem"
            certificate = directory / "cert.pem"
            configuration = directory / "openssl.cnf"
            configuration.write_text(
                "[req]\n"
                "distinguished_name=dn\n"
                "x509_extensions=ext\n"
                "prompt=no\n"
                "[dn]\nCN=app.example.test\n"
                "[ext]\nsubjectAltName=DNS:app.example.test\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-config",
                    str(configuration),
                    "-keyout",
                    str(key),
                    "-out",
                    str(certificate),
                ],
                check=True,
                capture_output=True,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            expected_certificate_sha256 = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(
                    certificate.read_text(encoding="ascii")
                )
            ).hexdigest()
            server = self.start_server(context)
            common = [
                sys.executable,
                str(PROBE_PATH),
                "--address",
                "127.0.0.1",
                "--port",
                str(server.server_port),
                "--hostname",
                "app.example.test",
                "--ca-file",
                str(certificate),
            ]

            https_result = subprocess.run(
                [*common, "https", "--path", "/ready"],
                check=True,
                capture_output=True,
                text=True,
            )
            websocket_result = subprocess.run(
                [*common, "websocket", "--path", "/socket", "--message", "hello"],
                check=True,
                capture_output=True,
                text=True,
            )
            ready = directory / "ready"
            proceed = directory / "proceed"
            session_process = subprocess.Popen(
                [
                    *common,
                    "session",
                    "--path",
                    "/socket",
                    "--ready-file",
                    str(ready),
                    "--continue-file",
                    str(proceed),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.addCleanup(
                lambda: session_process.kill()
                if session_process.poll() is None
                else None
            )
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists())
            proceed.touch()
            session_stdout, session_stderr = session_process.communicate(timeout=5)
            self.assertEqual(0, session_process.returncode, session_stderr)

        https = json.loads(https_result.stdout)
        websocket = json.loads(websocket_result.stdout)
        session = json.loads(session_stdout)
        self.assertEqual(200, https["status"])
        self.assertEqual(
            "fixture host=app.example.test path=/ready\n", https["body"]
        )
        self.assertEqual(expected_certificate_sha256, https["certificate_sha256"])
        self.assertEqual("hello", websocket["message"])
        self.assertIs(session["connection_preserved"], True)
        self.assertEqual("after-signal", session["message"])


if __name__ == "__main__":
    unittest.main()
