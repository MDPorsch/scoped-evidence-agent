"""M6, D-E38 to D-E45: the collector, the one program that opens a connection. Every test talks to a server on loopback (the
`loopback` marker allows exactly that and nothing else); every one pins something the design promises."""

from __future__ import annotations

import json
import socket
import ssl
from pathlib import Path
from typing import Any

import pytest

from scopedagent.adapters.pack import Pack
from scopedagent.domain.outcome import ErrorStatus
from scopedagent.live import collector
from scopedagent.live.collector import Refused, collect_operation, fetch, handshake, run_job, write_result
from scopedagent.live.protocol import Result
from scopedagent.live.ratelimit import RateLimiter
from tests.conftest import NetworkAttempt
from tests.support import assemble
from tests.support_live import (
    HOST,
    http_response,
    job_of,
    make_authority,
    make_server_certificate,
    operation,
    serve,
    server_context,
    trusting,
)

pytestmark = [pytest.mark.milestone("M6"), pytest.mark.loopback]

SECRET = assemble("tok_live-", "SYNTHETIC", "-0001")


def ok(body: bytes = b"hello", **headers: str) -> Any:
    return lambda request: http_response(200, {"Content-Type": "text/plain", **headers}, body)


# --------------------------------------------------------------------------------------------- the guard ----
def test_the_loopback_marker_allows_loopback_and_nothing_else() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(NetworkAttempt):
            sock.connect(("192.0.2.1", 80))
        with pytest.raises(NetworkAttempt):
            sock.bind(("0.0.0.0", 0))
        with pytest.raises(NetworkAttempt):
            sock.connect_ex(("8.8.8.8", 53))
    finally:
        sock.close()
    with pytest.raises(NetworkAttempt):
        socket.create_connection(("192.0.2.1", 80), timeout=1)
    with pytest.raises(NetworkAttempt):
        socket.getaddrinfo("example.com", None)
    with pytest.raises(NetworkAttempt):
        socket.gethostbyname("example.com")


# ---------------------------------------------------------------------------------------------- a request ----
def test_one_get_is_one_connection_with_exactly_the_documented_request() -> None:
    server, close = serve(ok(b"body", **{"X-Custom": "v"}))
    try:
        fetched = fetch(operation(server.port, path="/robots.txt"), job_of(), secret=None)
    finally:
        close()
    assert (fetched.status, fetched.body, fetched.headers["x-custom"]) == (200, b"body", ["v"])
    assert server.connections == 1
    lines = server.received[0].decode().split("\r\n")
    assert lines[0] == "GET /robots.txt HTTP/1.0"
    assert f"Host: {HOST}:{server.port}" in lines  # a non-default port is part of the Host header
    assert {"Accept: */*", "Accept-Encoding: identity", "Connection: close"} <= set(lines)
    assert any(line.startswith("User-Agent: scoped-agent/") for line in lines)
    assert not any(line.lower().startswith(("cookie", "authorization", "proxy", "origin")) for line in lines)


def test_the_default_port_is_left_out_of_the_host_header() -> None:
    plain = collector._request(operation(80), None).decode()
    assert f"Host: {HOST}\r\n" in plain
    secure = collector._request(operation(443, scheme="https"), None).decode()
    assert f"Host: {HOST}\r\n" in secure
    assert f"Host: {HOST}:8443\r\n" in collector._request(operation(8443, scheme="https"), None).decode()


def test_head_and_options_are_sent_as_they_are_and_options_carries_the_origin_only() -> None:
    server, close = serve(lambda r: http_response(204, {"Allow": "GET, HEAD, OPTIONS"}))
    try:
        fetch(operation(server.port, method="HEAD", path="/v1/health"), job_of(), secret=None)
        fetch(
            operation(server.port, method="OPTIONS", path="/v1/projects", origin="https://untrusted.example.invalid"),
            job_of(),
            secret=None,
        )
    finally:
        close()
    head, options = (r.decode().split("\r\n") for r in server.received)
    assert head[0] == "HEAD /v1/health HTTP/1.0" and not any(line.startswith("Origin") for line in head)
    assert options[0] == "OPTIONS /v1/projects HTTP/1.0"
    assert "Origin: https://untrusted.example.invalid" in options and "Access-Control-Request-Method: GET" in options


def test_a_redirect_is_returned_with_its_location_and_never_followed() -> None:
    server, close = serve(lambda r: http_response(302, {"Location": "http://169.254.169.254/latest/meta-data"}))
    try:
        fetched = fetch(operation(server.port), job_of(), secret=None)
    finally:
        close()
    assert fetched.status == 302 and fetched.headers["location"] == ["http://169.254.169.254/latest/meta-data"]
    assert (
        server.connections == 1
    )  # one request; the Location was not asked for (and could not be: the guard would stop it)


def test_a_credential_is_never_sent_over_plain_http_and_nothing_is_even_connected() -> None:
    server, close = serve(ok())
    try:
        with pytest.raises(Refused) as caught:
            fetch(operation(server.port), job_of(), secret=SECRET)
    finally:
        close()
    assert caught.value.status is ErrorStatus.REFUSED_BY_POLICY and server.connections == 0


def test_a_body_is_read_to_the_end_when_it_arrives_in_pieces() -> None:
    body = b"x" * 70_000
    server, close = serve(ok(body))
    try:
        assert fetch(operation(server.port), job_of(), secret=None).body == body
    finally:
        close()


def test_the_body_is_cut_one_byte_past_the_limit_so_the_adapter_can_see_it_was_truncated() -> None:
    server, close = serve(ok(b"y" * 5000))
    try:
        fetched = fetch(operation(server.port), job_of(max_bytes=1024), secret=None)
    finally:
        close()
    assert len(fetched.body) == 1025


def test_a_server_that_sends_the_head_and_the_start_of_the_body_together_is_read() -> None:
    server, close = serve(lambda r: b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nabcd")
    try:
        assert fetch(operation(server.port), job_of(), secret=None).body == b"abcd"
    finally:
        close()


# ---------------------------------------------------------------------------------------------- failures ----
@pytest.mark.parametrize(
    ("reply", "status"),
    [
        (b"garbage\r\n\r\n", ErrorStatus.PARSE_ERROR),
        (b"HTTP/1.0 abc OK\r\n\r\n", ErrorStatus.PARSE_ERROR),
        (b"HTTP/1.0\r\n\r\n", ErrorStatus.PARSE_ERROR),
        (b"NOTHTTP 200 OK\r\n\r\n", ErrorStatus.PARSE_ERROR),
        (b"HTTP/1.0 200 OK\r\nbad header line\r\n\r\n", ErrorStatus.PARSE_ERROR),
        (b"HTTP/1.0 200 OK\r\n : empty name\r\n\r\n", ErrorStatus.PARSE_ERROR),
        (b"HTTP/1.0 200 OK\r\nHeader : value\r\n\r\n", ErrorStatus.PARSE_ERROR),
        (b"HTTP/1.0 200 OK\r\nX: y\r\n", ErrorStatus.PARSE_ERROR),  # closed before the blank line
        (b"", ErrorStatus.PARSE_ERROR),
        (b"HTTP/1.0 200 OK\r\n" + b"X: " + b"a" * 70_000, ErrorStatus.SIZE_LIMIT),  # a head that never ends
        (b"HTTP/1.0 " + b"2" * 300 + b" OK\r\n\r\n", ErrorStatus.PARSE_ERROR),
    ],
)
def test_an_answer_that_is_not_http_is_a_recorded_error(reply: bytes, status: ErrorStatus) -> None:
    server, close = serve(lambda r: reply)
    try:
        with pytest.raises(Refused) as caught:
            fetch(operation(server.port), job_of(), secret=None)
    finally:
        close()
    assert caught.value.status is status


def test_a_connection_that_is_refused_is_a_recorded_error() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(Refused) as caught:
        fetch(operation(port), job_of(), secret=None)
    assert caught.value.status is ErrorStatus.HTTP_ERROR


def test_a_server_that_never_answers_times_out_inside_the_deadline() -> None:
    import time  # noqa: PLC0415

    server, close = serve(lambda r: None)  # accepts, reads the request, sends nothing, closes after our timeout
    started = time.monotonic()
    try:
        with pytest.raises(Refused) as caught:
            fetch(operation(server.port), job_of(timeout=1), secret=None)
    finally:
        close()
    assert caught.value.status in (ErrorStatus.TIMEOUT, ErrorStatus.PARSE_ERROR) and time.monotonic() - started < 5


def test_a_peer_that_is_not_the_pinned_address_is_refused_before_a_byte_is_sent() -> None:
    server, close = serve(ok())

    def connect(address: str, port: int, timeout: float) -> socket.socket:
        return socket.create_connection(("127.0.0.1", server.port), timeout)  # really connects to loopback

    try:
        with pytest.raises(Refused) as caught:
            fetch(operation(server.port, address="127.0.0.2"), job_of(), secret=None, connect=connect)
    finally:
        close()
    assert caught.value.status is ErrorStatus.REFUSED_BY_POLICY and server.received == []


def test_an_address_in_another_spelling_is_still_the_pinned_one() -> None:
    server, close = serve(ok())
    try:
        assert (
            fetch(
                operation(server.port, address="::ffff:127.0.0.1" if False else "127.0.0.1"), job_of(), secret=None
            ).status
            == 200
        )
    finally:
        close()
    assert collector._same_address("2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111")
    assert not collector._same_address("127.0.0.1", "127.0.0.2") and not collector._same_address(
        "nonsense", "127.0.0.1"
    )
    assert collector._same_address("fe80::1%eth0", "fe80::1")


# ----------------------------------------------------------------------------------------------- TLS -----
@pytest.fixture
def pki(tmp_path: Path) -> Any:
    return make_authority()


def tls_op(port: int, **over: Any) -> Any:
    return operation(port, scheme="https", **over)


def test_a_verified_connection_sends_the_request_and_gets_the_answer(
    tmp_path: Path, pki: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, key, _ = make_server_certificate(tmp_path, pki)
    monkeypatch.setattr(collector, "_context", trusting(pki))
    server, close = serve(ok(b"secure"), context=server_context(cert, key))
    try:
        fetched = fetch(tls_op(server.port), job_of(), secret=SECRET)
        fetch(tls_op(server.port), job_of(), secret=None)
    finally:
        close()
    first, second = (r.decode() for r in server.received)
    assert (
        fetched.body == b"secure" and f"Authorization: Bearer {SECRET}\r\n" in first and "Authorization" not in second
    )


@pytest.mark.parametrize("why", ["untrusted", "wrong-name", "expired"])
def test_a_certificate_that_fails_verification_gets_no_request_and_no_key(
    tmp_path: Path, pki: Any, monkeypatch: pytest.MonkeyPatch, why: str
) -> None:
    other = make_authority("Some Other CA")
    kwargs: dict[str, Any] = {
        "wrong-name": {"names": ("other.example.invalid",)},
        "expired": {"days_valid": 1, "days_ago": 5},
    }.get(why, {})
    cert, key, _ = make_server_certificate(tmp_path, other if why == "untrusted" else pki, **kwargs)
    monkeypatch.setattr(collector, "_context", trusting(pki))
    server, close = serve(ok(), context=server_context(cert, key))
    try:
        with pytest.raises(Refused) as caught:
            fetch(tls_op(server.port), job_of(), secret=SECRET)
    finally:
        close()
    assert (
        caught.value.status is ErrorStatus.TLS_FAILURE and server.received == []
    )  # nothing, and in particular not the key


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1:DeprecationWarning")
def test_a_server_that_only_speaks_old_tls_is_refused(
    tmp_path: Path, pki: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, key, _ = make_server_certificate(tmp_path, pki)
    monkeypatch.setattr(collector, "_context", trusting(pki))
    old = server_context(cert, key, maximum=ssl.TLSVersion.TLSv1_1, minimum=ssl.TLSVersion.TLSv1)
    server, close = serve(ok(), context=old)
    try:
        with pytest.raises(Refused) as caught:
            fetch(tls_op(server.port), job_of(), secret=None)
    except ssl.SSLError:  # pragma: no cover - a build of OpenSSL that cannot even offer TLS 1.1
        pytest.skip("this OpenSSL cannot serve TLS 1.1")
    finally:
        close()
    assert caught.value.status is ErrorStatus.TLS_FAILURE and server.received == []


def test_plain_text_on_an_https_port_is_a_tls_failure_and_nothing_is_sent() -> None:
    server, close = serve(ok())
    try:
        with pytest.raises(Refused) as caught:
            fetch(tls_op(server.port), job_of(), secret=SECRET)
    finally:
        close()
    assert caught.value.status is ErrorStatus.TLS_FAILURE and not any(SECRET.encode() in r for r in server.received)


def test_the_default_context_verifies_the_name_and_the_chain_and_wants_tls_12() -> None:
    context = collector._context(verify=True)
    assert context.verify_mode is ssl.CERT_REQUIRED and context.check_hostname is True
    assert context.minimum_version is ssl.TLSVersion.TLSv1_2
    unverified = collector._context(verify=False)
    assert unverified.verify_mode is ssl.CERT_NONE and unverified.minimum_version is ssl.TLSVersion.TLSv1_2


# ----------------------------------------------------------------------------------------- tls_metadata ----
def test_the_certificate_facts_are_recorded_even_when_the_certificate_does_not_verify(tmp_path: Path) -> None:
    cert, key, certificate = make_server_certificate(tmp_path, None, names=(HOST, "www.example.invalid"))  # self-signed
    server, close = serve(ok(), context=server_context(cert, key), read_request=False)
    try:
        entry = handshake(tls_op(server.port, kind="tls_metadata"), job_of())
    finally:
        close()
    facts = entry["certificate"]
    assert entry["status"] == "ok" and entry["version"] in ("TLSv1.2", "TLSv1.3")
    assert (facts["subject_cn"], facts["issuer_cn"], facts["self_signed"]) == (HOST, HOST, True)
    assert facts["san_dns"] == [HOST, "www.example.invalid"]
    assert facts["public_key"] == {"type": "ec", "bits": 256} and facts["signature_algorithm"] == "ecdsa-with-SHA256"
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415

    assert facts["sha256_fingerprint"] == certificate.fingerprint(hashes.SHA256()).hex()
    assert facts["not_before"].endswith("Z") and facts["not_after"].endswith("Z")
    assert server.received == []  # nothing was sent after the handshake


def test_an_issuer_other_than_the_subject_is_not_self_signed_and_rsa_keys_report_their_size(
    tmp_path: Path, pki: Any
) -> None:
    cert, key, _ = make_server_certificate(tmp_path, pki, rsa_bits=2048)
    server, close = serve(ok(), context=server_context(cert, key), read_request=False)
    try:
        facts = handshake(tls_op(server.port, kind="tls_metadata"), job_of())["certificate"]
    finally:
        close()
    assert facts["self_signed"] is False and facts["issuer_cn"] == "Test Lab CA"
    assert facts["public_key"] == {"type": "rsa", "bits": 2048} and "sha256" in facts["signature_algorithm"].lower()


def test_an_expired_certificate_is_still_described(tmp_path: Path) -> None:
    cert, key, _ = make_server_certificate(tmp_path, None, days_valid=1, days_ago=10)
    server, close = serve(ok(), context=server_context(cert, key), read_request=False)
    try:
        facts = handshake(tls_op(server.port, kind="tls_metadata"), job_of())["certificate"]
    finally:
        close()
    assert facts["not_after"] < facts["not_before"] or facts["not_after"] != facts["not_before"]


@pytest.mark.parametrize("serve_plain", [True, False])
def test_a_handshake_that_fails_is_recorded_as_such(serve_plain: bool) -> None:
    if serve_plain:
        server, close = serve(ok())
        port = server.port
    else:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        close = lambda: None  # noqa: E731
    try:
        entry = handshake(tls_op(port, kind="tls_metadata"), job_of())
    finally:
        close()
    assert entry == {"status": "handshake_failed" if serve_plain else "error", "version": None, "certificate": None}


def test_tls_metadata_over_plain_http_is_an_error_not_a_certificate() -> None:
    server, close = serve(ok())
    try:
        assert handshake(operation(server.port, kind="tls_metadata"), job_of()) == {
            "status": "error",
            "version": None,
            "certificate": None,
        }
    finally:
        close()


# ------------------------------------------------------------------------------------ the operations ----
def run(op: Any, environ: dict[str, str] | None = None, **job: Any) -> Any:
    import asyncio  # noqa: PLC0415

    return asyncio.run(collect_operation(op, job_of(op, **job), environ or {}))


def test_a_web_page_becomes_the_same_envelope_an_offline_run_would_make_and_keeps_a_redacted_artifact() -> None:
    server, close = serve(
        lambda r: http_response(
            200,
            {"Content-Type": "text/plain", "Set-Cookie": f"s={SECRET}"},
            b"Contact: mailto:security@lab.example.invalid\n",
        )
    )
    try:
        result = run(operation(server.port, path="/.well-known/security.txt"))
    finally:
        close()
    payload = result.envelope.payload
    assert result.envelope.error_status is ErrorStatus.OK and result.envelope.adapter == "offline_http"
    assert payload.headers["set-cookie"] == ["[REDACTED]"] and payload.body.parsed["contact"] == [
        "mailto:security@lab.example.invalid"
    ]
    assert (
        result.body == b"Contact: mailto:security@lab.example.invalid\n"
        and SECRET not in result.envelope.model_dump_json()
    )


def test_an_api_read_keeps_the_shape_and_no_artifact() -> None:
    server, close = serve(
        lambda r: http_response(
            200, {"Content-Type": "application/json"}, b'{"id": "p-1001", "name": "SYNTHETIC-NAME"}'
        )
    )
    op = operation(
        server.port,
        kind="api_read",
        path="/v1/projects/p-1001",
        target_id="orders-api",
        principal="tenant-a-user",
        endpoint_id="get-project",
        params={"project_id": "p-1001"},
    )
    try:
        result = run(op)
    finally:
        close()
    assert result.body is None and "SYNTHETIC-NAME" not in result.envelope.model_dump_json()
    assert [e.path for e in result.envelope.payload.shape] == [
        "$",
        "$.id",
        "$.name",
    ] and result.envelope.payload.principal == "tenant-a-user"


def test_an_api_options_request_records_the_cors_answer() -> None:
    server, close = serve(lambda r: http_response(204, {"Allow": "GET, HEAD", "Access-Control-Allow-Origin": "*"}))
    op = operation(
        server.port,
        kind="api_options",
        method="OPTIONS",
        path="/v1/projects",
        target_id="orders-api",
        principal="anonymous",
        endpoint_id="list-projects",
        origin="https://untrusted.example.invalid",
    )
    try:
        payload = run(op).envelope.payload
    finally:
        close()
    assert (
        payload.allow == ["GET", "HEAD"]
        and payload.cors.allow_origin == "*"
        and payload.origin == "https://untrusted.example.invalid"
    )


def test_an_ai_model_list_is_read_with_the_credential_from_the_environment(
    tmp_path: Path, pki: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, key, _ = make_server_certificate(tmp_path, pki)
    monkeypatch.setattr(collector, "_context", trusting(pki))
    server, close = serve(
        lambda r: http_response(
            200, {"Content-Type": "application/json"}, b'{"object": "list", "data": [{"id": "support-bot-1"}]}'
        ),
        context=server_context(cert, key),
    )
    op = tls_op(server.port, kind="ai_metadata", path="/v1/models", target_id="support-bot", credential_env="BOT_KEY")
    try:
        result = run(op, {"BOT_KEY": SECRET})
    finally:
        close()
    assert result.envelope.payload.model_ids == ["support-bot-1"]
    assert (
        f"Authorization: Bearer {SECRET}" in server.received[0].decode()
        and SECRET not in result.envelope.model_dump_json()
    )


def test_a_credential_that_was_promised_and_is_missing_means_nothing_is_sent() -> None:
    server, close = serve(ok())
    try:
        result = run(
            operation(
                server.port, kind="ai_metadata", path="/v1/models", target_id="support-bot", credential_env="BOT_KEY"
            ),
            {},
        )
    finally:
        close()
    assert result.envelope.error_status is ErrorStatus.REFUSED_BY_POLICY and server.connections == 0


def test_a_refused_or_failed_request_is_an_error_observation_with_a_valid_empty_payload() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    result = run(operation(port))
    assert result.envelope.error_status is ErrorStatus.HTTP_ERROR and result.envelope.payload.http_status is None


def test_a_body_over_the_limit_is_a_recorded_size_limit() -> None:
    server, close = serve(ok(b"z" * 4000))
    try:
        result = run(operation(server.port), max_bytes=1024)
    finally:
        close()
    assert result.envelope.error_status is ErrorStatus.SIZE_LIMIT


def test_a_tls_metadata_operation_is_normalised_like_an_offline_one(tmp_path: Path) -> None:
    cert, key, _ = make_server_certificate(tmp_path, None)
    server, close = serve(ok(), context=server_context(cert, key), read_request=False)
    try:
        result = run(tls_op(server.port, kind="tls_metadata", path=None))
    finally:
        close()
    assert (
        result.envelope.observation_type == "tls_metadata" and result.envelope.payload.certificate.self_signed is True
    )


def test_the_pack_the_adapters_read_is_only_ever_the_one_answer() -> None:
    section, key = collector._pack_key(operation(8080, path="/x"))
    assert (section, key) == ("http", f"http://{HOST}:8080/x")
    assert collector._pack_key(operation(443, kind="tls_metadata", scheme="https", path=None)) == ("tls", f"{HOST}:443")
    assert (
        collector._pack_key(operation(443, kind="ai_metadata", scheme="https", path="/v1/models", target_id="b"))[0]
        == "ai"
    )
    section, key = collector._pack_key(
        operation(443, kind="api_read", scheme="https", path="/v1/p", target_id="t", principal="u1", method="GET")
    )
    assert section == "api" and key == f"u1|GET|https://{HOST}:443/v1/p"
    assert isinstance(Pack("x", {}, {}, {}, {}, {}), Pack)


# --------------------------------------------------------------------------------------------- the files ----
def test_a_job_is_run_serially_within_the_rate_and_each_result_is_written_as_plain_files(tmp_path: Path) -> None:
    server, close = serve(ok(b"page"))
    waits: list[int] = []

    class Counting(RateLimiter):
        def wait(self) -> float:
            waits.append(1)
            return super().wait()

    ops = [operation(server.port, index=i, path=f"/p{i}") for i in range(3)]
    try:
        written = run_job(job_of(*ops), tmp_path, {}, limiter=Counting(10))
    finally:
        close()
    assert written == 3 and len(waits) == 3 and server.connections == 3
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        [f"result-{i}.json" for i in range(3)] + [f"artifact-{i}.bin" for i in range(3)]
    )
    record = Result.model_validate_json((tmp_path / "result-1.json").read_text())
    assert record.index == 1 and record.artifact is not None and record.artifact.file == "artifact-1.bin"
    assert (tmp_path / "artifact-1.bin").read_bytes() == b"page"


def test_a_result_without_a_body_has_no_artifact_file(tmp_path: Path) -> None:
    server, close = serve(lambda r: http_response(200, {"Content-Type": "application/json"}, b"{}"))
    op = operation(
        server.port,
        kind="api_read",
        path="/v1/x",
        target_id="orders-api",
        principal="anonymous",
        endpoint_id="get-project",
    )
    try:
        written = run_job(job_of(op), tmp_path, {}, limiter=RateLimiter(10))
    finally:
        close()
    assert written == 1 and [p.name for p in tmp_path.iterdir()] == ["result-0.json"]
    assert json.loads((tmp_path / "result-0.json").read_text())["artifact"] is None


def test_write_result_keeps_the_sha256_of_the_artifact_it_wrote(tmp_path: Path) -> None:
    import hashlib  # noqa: PLC0415

    server, close = serve(ok(b"abc"))
    try:
        result = run(operation(server.port))
    finally:
        close()
    write_result(tmp_path, 7, result)
    record = Result.model_validate_json((tmp_path / "result-7.json").read_text())
    assert (
        record.artifact is not None
        and record.artifact.sha256 == hashlib.sha256(b"abc").hexdigest()
        and record.artifact.size == 3
    )


# ------------------------------------------------------------------------------------------ the odd paths ----
def stalled_port() -> tuple[socket.socket, int]:
    """A listener that never accepts: a connection to it succeeds and then nothing ever answers."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    return listener, listener.getsockname()[1]


def test_a_connect_that_times_out_is_a_recorded_timeout() -> None:
    def connect(address: str, port: int, timeout: float) -> socket.socket:
        raise TimeoutError

    with pytest.raises(Refused) as caught:
        fetch(operation(1), job_of(), secret=None, connect=connect)
    assert caught.value.status is ErrorStatus.TIMEOUT


def test_a_server_that_accepts_and_never_answers_is_a_recorded_timeout_for_http_and_for_a_tls_handshake() -> None:
    listener, port = stalled_port()
    try:
        with pytest.raises(Refused) as plain:
            fetch(operation(port), job_of(timeout=1), secret=None)
        with pytest.raises(Refused) as secure:
            fetch(tls_op(port), job_of(timeout=1), secret=None)
        entry = handshake(tls_op(port, kind="tls_metadata"), job_of(timeout=1))
    finally:
        listener.close()
    assert plain.value.status is ErrorStatus.TIMEOUT and secure.value.status is ErrorStatus.TIMEOUT
    assert entry == {"status": "timeout", "version": None, "certificate": None}


def test_the_overall_deadline_ends_a_body_that_trickles_in() -> None:
    server, close = serve(ok(b"b" * 100))
    ticks = iter([0.0, 0.0, 99.0, 99.0, 99.0])  # the deadline passes between the head and the body
    try:
        with pytest.raises(Refused) as caught:
            fetch(operation(server.port), job_of(timeout=5), secret=None, clock=lambda: next(ticks))
    finally:
        close()
    assert caught.value.status is ErrorStatus.TIMEOUT


def test_a_connection_that_is_reset_mid_answer_is_a_recorded_error() -> None:
    import struct  # noqa: PLC0415

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def reset() -> None:
        conn, _ = listener.accept()
        conn.recv(4096)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))  # close sends a reset
        conn.close()

    import threading  # noqa: PLC0415

    thread = threading.Thread(target=reset, daemon=True)
    thread.start()
    try:
        with pytest.raises(Refused) as caught:
            fetch(operation(port), job_of(), secret=None)
    finally:
        thread.join(timeout=3)
        listener.close()
    assert caught.value.status is ErrorStatus.HTTP_ERROR


def test_a_certificate_with_no_alternative_names_has_none_listed(tmp_path: Path, pki: Any) -> None:
    cert, key, _ = make_server_certificate(tmp_path, pki, san=False)
    server, close = serve(ok(), context=server_context(cert, key), read_request=False)
    try:
        facts = handshake(tls_op(server.port, kind="tls_metadata"), job_of())["certificate"]
    finally:
        close()
    assert facts["san_dns"] == [] and facts["subject_cn"] == HOST


@pytest.mark.parametrize(
    ("make", "expected"),
    [
        ("ed25519", {"type": "ed25519", "bits": 256}),
        ("ed448", {"type": "ed448", "bits": 456}),
        ("x25519", {"type": "unknown", "bits": None}),
    ],
)
def test_the_public_key_kinds_a_certificate_may_carry_are_named(make: str, expected: dict[str, Any]) -> None:
    import datetime as dt  # noqa: PLC0415

    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x25519  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415

    keys = {"ed25519": ed25519.Ed25519PrivateKey, "ed448": ed448.Ed448PrivateKey, "x25519": x25519.X25519PrivateKey}
    key = keys[make].generate()
    signer = ed25519.Ed25519PrivateKey.generate()  # x25519 cannot sign: the certificate is issued by another key
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "k")])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
        .sign(signer, None)
    )  # fmt: skip
    assert collector._certificate(certificate.public_bytes(serialization.Encoding.DER))["public_key"] == expected
    assert hashes is not None


def test_a_handshake_that_yields_no_certificate_or_an_old_version_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest import mock  # noqa: PLC0415

    for der, version in ((b"", "TLSv1.3"), (b"x", "TLSv1.1")):
        stub = mock.create_autospec(ssl.SSLSocket, instance=True)
        stub.getpeercert.return_value, stub.version.return_value = der, version
        monkeypatch.setattr(collector, "_open", lambda *a, _s=stub, **k: _s)
        assert handshake(tls_op(443, kind="tls_metadata"), job_of()) == {
            "status": "error",
            "version": None,
            "certificate": None,
        }
