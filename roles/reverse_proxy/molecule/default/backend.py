#!/usr/bin/env python3
"""Disposable HTTP and WebSocket echo backend for Molecule."""

from __future__ import annotations

import argparse
import base64
import hashlib
import struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _read_exact(stream, length: int) -> bytes:
    value = stream.read(length)
    if len(value) != length:
        raise ConnectionError("incomplete WebSocket frame")
    return value


def _read_frame(stream) -> tuple[int, bytes]:
    first, second = _read_exact(stream, 2)
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _read_exact(stream, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _read_exact(stream, 8))[0]
    mask = _read_exact(stream, 4) if second & 0x80 else b""
    payload = _read_exact(stream, length)
    if mask:
        payload = bytes(
            value ^ mask[index % 4] for index, value in enumerate(payload)
        )
    return opcode, payload


def _write_frame(stream, opcode: int, payload: bytes) -> None:
    first = bytes((0x80 | opcode,))
    if len(payload) < 126:
        header = first + bytes((len(payload),))
    elif len(payload) <= 0xFFFF:
        header = first + bytes((126,)) + struct.pack("!H", len(payload))
    else:
        header = first + bytes((127,)) + struct.pack("!Q", len(payload))
    stream.write(header + payload)
    stream.flush()


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, format_string: str, *arguments: object) -> None:
        del format_string, arguments

    def do_GET(self) -> None:
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self._websocket()
            return

        body = (
            f"fixture host={self.headers.get('Host', '')} path={self.path}\n"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _websocket(self) -> None:
        websocket_key = self.headers.get("Sec-WebSocket-Key", "")
        if not websocket_key:
            self.send_error(400)
            return
        accept = base64.b64encode(
            hashlib.sha1(
                (websocket_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode(
                    "ascii"
                ),
                usedforsecurity=False,
            ).digest()
        ).decode("ascii")
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

        while True:
            try:
                opcode, payload = _read_frame(self.rfile)
            except ConnectionError:
                return
            if opcode == 8:
                _write_frame(self.wfile, 8, b"")
                return
            if opcode != 1:
                _write_frame(self.wfile, 8, b"")
                return
            _write_frame(self.wfile, 1, payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True, type=int)
    arguments = parser.parse_args()
    ThreadingHTTPServer(("127.0.0.1", arguments.port), FixtureHandler).serve_forever()


if __name__ == "__main__":
    main()
