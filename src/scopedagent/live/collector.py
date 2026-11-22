"""The collector: the one program that opens a network connection (D-E38). It runs inside the isolated container, after the firewall
and the self-test, as an unprivileged user, and does exactly what the job says.

* It connects only to the pinned address of each operation (it resolves nothing), and reads the peer address back to confirm it.
* TLS 1.2 or newer, verified against the system trust store with the declared host name, **before** a single request byte is sent.
  A failed verification sends nothing. `tls_metadata` alone may complete a handshake whose certificate fails, because it sends nothing
  afterwards: it only records what the certificate says.
* HTTP/1.0 with a `Host` header, `Connection: close`, `Accept-Encoding: identity`: no chunked framing, no keep-alive, no redirects
  followed, no proxy, no cookie. A credential travels only as `Authorization: Bearer` to the declared host over verified TLS.
* What comes back is normalised by the same adapters that read a fixture pack (`adapters/offline.py`): validated, redacted, capped and
  parsed into bounded facts. Only an envelope and a redacted artifact are written to the output directory.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scopedagent import __version__
from scopedagent.adapters.base import Adapter, AdapterResult
from scopedagent.adapters.offline import (
    OfflineAiMetadata,
    OfflineApiOptions,
    OfflineApiRead,
    OfflineApiSpec,
    OfflineHttp,
    OfflineTls,
    error_result,
)
from scopedagent.adapters.pack import Pack
from scopedagent.domain.outcome import ErrorStatus
from scopedagent.live.protocol import ArtifactRef, Job, JobOperation, Result
from scopedagent.live.ratelimit import RateLimiter

MAX_HEADER_BYTES = 64 * 1024
MAX_STATUS_LINE = 256

Connect = Callable[[str, int, float], socket.socket]


class Refused(Exception):
    """A request that was not made, or whose answer cannot be trusted. `status` is what is recorded."""

    def __init__(self, status: ErrorStatus) -> None:
        super().__init__(status.value)
        self.status = status


@dataclass(frozen=True)
class Fetched:
    status: int
    headers: dict[str, list[str]]
    body: bytes  # at most max_response_bytes + 1: one byte more than allowed marks a truncated answer


def default_connect(address: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((address, port), timeout=timeout)


def _same_address(left: str, right: str) -> bool:
    try:
        return ipaddress.ip_address(left.split("%", maxsplit=1)[0]) == ipaddress.ip_address(right)
    except ValueError:
        return False


def _context(*, verify: bool) -> ssl.SSLContext:
    context = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if not verify:  # only for tls_metadata, which sends nothing after the handshake
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _open(op: JobOperation, timeout: float, connect: Connect, *, verify: bool = True) -> socket.socket | ssl.SSLSocket:
    """A connection to the pinned address, confirmed, with TLS completed (and verified) before it is returned."""
    try:
        raw = connect(op.address, op.port, timeout)
    except TimeoutError:
        raise Refused(ErrorStatus.TIMEOUT) from None
    except OSError:
        raise Refused(ErrorStatus.HTTP_ERROR) from None
    try:
        raw.settimeout(timeout)
        if not _same_address(str(raw.getpeername()[0]), op.address):
            raise Refused(ErrorStatus.REFUSED_BY_POLICY)  # the peer is not the pinned address: nothing is sent
        if op.scheme == "http":
            return raw
        return _context(verify=verify).wrap_socket(raw, server_hostname=op.host)
    except ssl.SSLCertVerificationError:
        raw.close()
        raise Refused(ErrorStatus.TLS_FAILURE) from None
    except (ssl.SSLError, ConnectionError):
        raw.close()
        raise Refused(ErrorStatus.TLS_FAILURE) from None
    except TimeoutError:
        raw.close()
        raise Refused(ErrorStatus.TIMEOUT) from None
    except BaseException:
        raw.close()
        raise


def _request(op: JobOperation, secret: str | None) -> bytes:
    default_port = 443 if op.scheme == "https" else 80
    host = op.host if op.port == default_port else f"{op.host}:{op.port}"
    lines = [
        f"{op.method} {op.path} HTTP/1.0",
        f"Host: {host}",
        f"User-Agent: scoped-agent/{__version__}",
        "Accept: */*",
        "Accept-Encoding: identity",
        "Connection: close",
    ]
    if op.method == "OPTIONS" and op.origin:
        lines += [f"Origin: {op.origin}", "Access-Control-Request-Method: GET"]
    if secret:
        lines.append(f"Authorization: Bearer {secret}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def _parse_head(raw: bytes) -> tuple[int, dict[str, list[str]]]:
    lines = raw.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit() or len(lines[0]) > MAX_STATUS_LINE:
        raise Refused(ErrorStatus.PARSE_ERROR)
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if not separator or not name or name != name.strip():
            raise Refused(ErrorStatus.PARSE_ERROR)
        headers.setdefault(name.lower(), []).append(value.strip())
    return int(parts[1]), headers


def fetch(
    op: JobOperation,
    job: Job,
    *,
    secret: str | None,
    connect: Connect = default_connect,
    clock: Callable[[], float] = time.monotonic,
) -> Fetched:
    """One request, one connection, read to the end or to the cap, inside one overall deadline."""
    if secret and op.scheme != "https":
        raise Refused(
            ErrorStatus.REFUSED_BY_POLICY
        )  # a credential is never sent in the clear: nothing is even connected
    timeout = float(job.per_request_timeout_seconds)
    deadline = clock() + timeout
    conn = _open(op, timeout, connect)
    try:
        conn.sendall(_request(op, secret))
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            if len(buffer) > MAX_HEADER_BYTES or clock() > deadline:
                raise Refused(ErrorStatus.SIZE_LIMIT if len(buffer) > MAX_HEADER_BYTES else ErrorStatus.TIMEOUT)
            chunk = conn.recv(8192)
            if not chunk:
                raise Refused(ErrorStatus.PARSE_ERROR)
            buffer += chunk
        head, _, body = buffer.partition(b"\r\n\r\n")
        status, headers = _parse_head(head)
        limit = job.max_response_bytes + 1
        chunks = [body[:limit]]
        total = len(chunks[0])
        while total < limit:
            if clock() > deadline:
                raise Refused(ErrorStatus.TIMEOUT)
            chunk = conn.recv(min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return Fetched(status, headers, b"".join(chunks))
    except TimeoutError:
        raise Refused(ErrorStatus.TIMEOUT) from None
    except (OSError, ssl.SSLError):
        raise Refused(ErrorStatus.HTTP_ERROR) from None
    finally:
        conn.close()


def _certificate(der: bytes) -> dict[str, Any]:
    """The facts of a certificate, read with `cryptography` (installed in the container image only)."""
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    cert = x509.load_der_x509_certificate(der)

    def common_name(name: x509.Name) -> str:
        values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(values[0].value) if values else ""

    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName
        )
    except x509.ExtensionNotFound:
        names = []
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        public_key: dict[str, Any] = {"type": "rsa", "bits": key.key_size}
    elif isinstance(key, ec.EllipticCurvePublicKey):
        public_key = {"type": "ec", "bits": key.curve.key_size}
    elif isinstance(key, ed25519.Ed25519PublicKey):
        public_key = {"type": "ed25519", "bits": 256}
    elif isinstance(key, ed448.Ed448PublicKey):
        public_key = {"type": "ed448", "bits": 456}
    else:
        public_key = {"type": "unknown", "bits": None}
    return {
        "subject_cn": common_name(cert.subject),
        "issuer_cn": common_name(cert.issuer),
        "san_dns": list(names)[:100],
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "signature_algorithm": getattr(
            cert.signature_algorithm_oid, "_name", cert.signature_algorithm_oid.dotted_string
        ),
        "public_key": public_key,
        "self_signed": cert.issuer == cert.subject,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
    }


def handshake(op: JobOperation, job: Job, *, connect: Connect = default_connect) -> dict[str, Any]:
    """A `tls_metadata` entry: what the certificate says, whether or not it verifies. Nothing is sent after the handshake."""
    timeout = float(job.per_request_timeout_seconds)
    try:
        conn = _open(op, timeout, connect, verify=False)
    except Refused as refused:
        status = {ErrorStatus.TIMEOUT: "timeout", ErrorStatus.TLS_FAILURE: "handshake_failed"}.get(
            refused.status, "error"
        )
        return {"status": status, "version": None, "certificate": None}
    try:
        if not isinstance(conn, ssl.SSLSocket):
            return {"status": "error", "version": None, "certificate": None}
        der = conn.getpeercert(binary_form=True)
        version = conn.version()
    finally:
        conn.close()
    if not der or version not in ("TLSv1.2", "TLSv1.3"):
        return {"status": "error", "version": None, "certificate": None}
    return {"status": "ok", "version": version, "certificate": _certificate(der)}


# ------------------------------------------------------------------------------------------ the run ----
def _entry(fetched: Fetched) -> dict[str, Any]:
    entry: dict[str, Any] = {"status": fetched.status, "headers": fetched.headers}
    if fetched.body:
        entry["body_base64"] = base64.b64encode(fetched.body).decode("ascii")
    return entry


def _adapters(job: Job, pack: Pack, api_limits: Mapping[str, int]) -> dict[str, Adapter]:
    limit = job.max_response_bytes
    return {
        "tls_metadata": OfflineTls(pack),
        "http_metadata": OfflineHttp(pack, limit),
        "ai_metadata": OfflineAiMetadata(pack, limit),
        "api_spec": OfflineApiSpec(pack, api_limits),
        "api_read": OfflineApiRead(pack, api_limits),
        "api_options": OfflineApiOptions(pack, api_limits),
    }


def _pack_key(op: JobOperation) -> tuple[str, str]:
    """(pack section, key) under which the offline adapter for this operation looks its answer up."""
    from scopedagent.adapters.offline import _api_key, _key  # noqa: PLC0415

    planned = op.planned()
    if op.kind == "tls_metadata":
        return "tls", f"{op.host}:{op.port}"
    if op.kind == "http_metadata":
        return "http", _key(planned)
    if op.kind == "ai_metadata":
        return "ai", _key(planned)
    return "api", _api_key(planned)


async def collect_operation(
    op: JobOperation,
    job: Job,
    environ: Mapping[str, str],
    connect: Connect = default_connect,
) -> AdapterResult:
    """Fetch one operation and normalise the answer through the same adapters as an offline run."""
    section, key = _pack_key(op)
    secret = environ.get(op.credential_env) if op.credential_env else None
    if op.credential_env and not secret:
        return error_result(op.planned(), ErrorStatus.REFUSED_BY_POLICY)  # a credential was promised and is missing
    try:
        entry = (
            handshake(op, job, connect=connect)
            if op.kind == "tls_metadata"
            else _entry(fetch(op, job, secret=secret, connect=connect))
        )
    except Refused as refused:
        return error_result(op.planned(), refused.status)
    sections: dict[str, dict[str, dict[str, Any]]] = {"dns": {}, "tls": {}, "http": {}, "ai": {}, "api": {}}
    sections[section][key] = entry
    pack = Pack("live", sections["dns"], sections["tls"], sections["http"], sections["ai"], sections["api"])
    limits = {op.target_id: job.max_response_bytes} if op.target_id else {}
    return await _adapters(job, pack, limits)[op.kind].collect(op.planned())


def write_result(directory: Path, index: int, result: AdapterResult) -> None:
    """The envelope and its artifact as plain files in the output directory (and nothing else)."""
    artifact: ArtifactRef | None = None
    if result.body is not None:
        name = f"artifact-{index}.bin"
        (directory / name).write_bytes(result.body)
        artifact = ArtifactRef(
            file=name,
            mime=result.body_mime or "application/octet-stream",
            status=result.body_status,
            sha256=hashlib.sha256(result.body).hexdigest(),
            size=len(result.body),
        )
    record = Result(
        index=index,
        envelope=json.loads(result.envelope.model_dump_json()),
        source_hash=hashlib.sha256(result.source_bytes).hexdigest(),
        redactions=result.redactions,
        artifact=artifact,
    )
    (directory / f"result-{index}.json").write_text(record.model_dump_json(), encoding="utf-8")


def run_job(
    job: Job,
    directory: Path,
    environ: Mapping[str, str] = os.environ,
    *,
    connect: Connect = default_connect,
    limiter: RateLimiter | None = None,
) -> int:
    """Every operation in order, serially, within the rate limit. Returns how many were written."""
    limiter = limiter or RateLimiter(job.requests_per_second)
    written = 0
    for op in job.operations:
        limiter.wait()
        result = asyncio.run(collect_operation(op, job, environ, connect))
        write_result(directory, op.index, result)
        written += 1
    return written
