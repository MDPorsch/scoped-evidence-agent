"""Helpers for the live tests: a tiny loopback server (plain or TLS), certificates made on the fly, and jobs."""

from __future__ import annotations

import contextlib
import datetime as dt
import socket
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from scopedagent.live.protocol import Job, JobOperation

HOST = "lab.example.invalid"
Responder = Callable[[bytes], bytes | None]


@dataclass
class Server:
    port: int
    received: list[bytes] = field(default_factory=list)
    connections: int = 0


def http_response(status: int = 200, headers: dict[str, str] | None = None, body: bytes = b"") -> bytes:
    lines = [f"HTTP/1.0 {status} Test"] + [f"{k}: {v}" for k, v in (headers or {}).items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def serve(
    responder: Responder, *, context: ssl.SSLContext | None = None, read_request: bool = True
) -> tuple[Server, Callable[[], None]]:
    """Listen on a loopback port; for each connection read the request, record it, send `responder(request)`, close."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.2)
    server = Server(listener.getsockname()[1])
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            server.connections += 1
            try:
                raw.settimeout(3)
                conn: Any = context.wrap_socket(raw, server_side=True) if context else raw
                data = b""
                while read_request and b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if data:
                    server.received.append(data)
                reply = responder(data)
                if reply:
                    conn.sendall(reply)
                conn.close()
            except (OSError, ssl.SSLError):
                with contextlib.suppress(OSError):
                    raw.close()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()

    def close() -> None:
        stop.set()
        thread.join(timeout=3)
        listener.close()

    return server, close


# ------------------------------------------------------------------------------------------ certificates ----
@dataclass
class Authority:
    certificate: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_authority(common_name: str = "Test Lab CA") -> Authority:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name)).issuer_name(_name(common_name))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    return Authority(certificate, key)


def make_server_certificate(
    directory: Path,
    authority: Authority | None,
    *,
    names: tuple[str, ...] = (HOST,),
    days_valid: int = 30,
    days_ago: int = 1,
    rsa_bits: int | None = None,
    san: bool = True,
) -> tuple[Path, Path, x509.Certificate]:
    """A leaf certificate (self-signed when `authority` is None). Returns (certificate file, key file, the certificate)."""
    key: Any = (
        rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        if rsa_bits
        else ec.generate_private_key(ec.SECP256R1())
    )
    now = dt.datetime.now(dt.UTC)
    issuer = authority.certificate.subject if authority else _name(names[0])
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(names[0])).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=days_ago)).not_valid_after(now - dt.timedelta(days=days_ago) + dt.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )  # fmt: skip
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    if authority:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.key.public_key()), critical=False
        )
    certificate = builder.sign(authority.key if authority else key, hashes.SHA256())
    cert_file, key_file = directory / f"{names[0]}.pem", directory / f"{names[0]}.key"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_file, key_file, certificate


def server_context(
    cert_file: Path, key_file: Path, *, maximum: ssl.TLSVersion | None = None, minimum: ssl.TLSVersion | None = None
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    if maximum is not None:
        context.maximum_version = maximum
    if minimum is not None:
        context.minimum_version = minimum
    return context


def trusting(authority: Authority) -> Callable[..., ssl.SSLContext]:
    """A replacement for the collector's `_context(verify=...)` that trusts one test CA (verification stays fully on)."""

    def context(*, verify: bool) -> ssl.SSLContext:
        if not verify:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            return ctx
        ctx = ssl.create_default_context(cadata=authority.pem.decode())
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    return context


# --------------------------------------------------------------------------------------------------- jobs ----
def operation(port: int, **over: Any) -> JobOperation:
    values: dict[str, Any] = {
        "index": 0, "kind": "http_metadata", "host": HOST, "scheme": "http", "port": port, "address": "127.0.0.1",
        "path": "/", "method": "GET",
    }  # fmt: skip
    values.update(over)
    return JobOperation(**values)


def job_of(*operations: JobOperation, max_bytes: int = 100_000, timeout: int = 5, rate: int = 10) -> Job:
    return Job(
        max_response_bytes=max_bytes,
        per_request_timeout_seconds=timeout,
        requests_per_second=rate,
        operations=list(operations),
    )
