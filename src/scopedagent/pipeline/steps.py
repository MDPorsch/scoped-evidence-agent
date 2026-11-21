"""Validation steps: a rule supplies a typed spec, a fixed template supplies every sentence, a checker drops what fails (D-E58, D-E59).

A step is something a PERSON may do to confirm or refute one condition of a draft. The checker runs before a draft is stored:

    VS-01  the kind is on the closed list and the intrusiveness matches it
    VS-02  every host, port, scheme, path, origin and probe is in the scope, for an operation the scope allows
    VS-03  every value that reaches a template is plain and shell-safe
    VS-05  the step cites observations of this draft, and a comparison cites two different ones
    VS-06  it is the ninth step, or its action is over the limit

A dropped step is reported with its rule; nothing disappears silently. Target text can appear only in `record`, as quoted data.
No kind sends a payload, a credential, a body, a state-changing method, a request to an unlisted path or host, or a repeated request.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from scopedagent.domain.findings import (
    INTRUSIVENESS,
    INVOCATION_KINDS,
    MAX_STEPS,
    DroppedStep,
    StepKind,
    StepTarget,
    ValidationStep,
)
from scopedagent.errors import ScopeError
from scopedagent.logs import safe_text
from scopedagent.policy.probes import PROBE_SETS
from scopedagent.policy.scope import ScopeConfig, canonical_host, canonical_path

MAX_ACTION = 400
MAX_QUOTED = 3
QUOTED_LIMIT = 80
MAX_QUESTION = 200
RECORD_TYPES = frozenset({"A", "AAAA", "CNAME", "NS", "MX", "TXT", "CAA"})
_FIELD = re.compile(r"[a-z][a-z0-9_.-]{0,39}")
_ORIGIN = re.compile(r"https://[a-z0-9][a-z0-9.-]{0,251}(:[0-9]{1,5})?")
_DEFAULT_PORT = {"https": 443, "http": 80}
_BANNED = re.compile(r"[;|&$`><()\n\r]")
# no scope can declare an origin until API targets exist (D-E48), so no origin is valid yet
_CORS_ORIGINS: frozenset[str] = frozenset()


@dataclass(frozen=True)
class StepSpec:
    """What a rule asks for. Every field is a value to be checked; none is prose."""

    kind: str
    cites: tuple[str, ...]
    condition: str
    intrusiveness: str | None = None
    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    path: str | None = None
    method: str = "GET"
    record_type: str | None = None
    origin: str | None = None
    target_id: str | None = None
    probe_set: str | None = None
    probe_index: int | None = None
    fields: tuple[str, ...] = ()
    quoted: tuple[str, ...] = ()
    question: str | None = None


class _Drop(Exception):
    def __init__(self, rule: str) -> None:
        super().__init__(rule)
        self.rule = rule


def _url(scheme: str, host: str, port: int, path: str) -> str:
    shown = "" if _DEFAULT_PORT.get(scheme) == port else f":{port}"
    return f"{scheme}://{host}{shown}{path}"


def invocation_for(
    kind: StepKind,
    *,
    host: str = "",
    port: int = 0,
    scheme: str = "https",
    path: str = "/",
    method: str = "GET",
    record_type: str = "A",
    origin: str = "",
) -> str | None:
    """The one command a kind may show, from a fixed template: verification on, no body, no credential, no redirect, one request."""
    if kind is StepKind.INSPECT_CERTIFICATE_FIELD:
        return f"openssl s_client -connect {host}:{port} -servername {host} -verify_return_error"
    if kind is StepKind.REREQUEST_LISTED_PATH:
        target = _url(scheme, host, port, path)
        if method == "HEAD":
            return f"curl --silent --show-error --head --max-time 10 --max-redirs 0 {target}"
        return f"curl --silent --show-error --dump-header - --output /dev/null --max-time 10 --max-redirs 0 {target}"
    if kind is StepKind.READ_PUBLIC_DOCUMENT:
        return f"curl --silent --show-error --max-time 10 --max-redirs 0 {_url(scheme, host, port, path)}"
    if kind is StepKind.RE_RESOLVE_NAME:
        return f"dig +noall +answer {host} {record_type}"
    if kind is StepKind.CHECK_CORS_FOR_DECLARED_ORIGIN:
        return (
            f"curl --silent --show-error --request OPTIONS --header 'Origin: {origin}' --dump-header - "
            f"--output /dev/null --max-time 10 --max-redirs 0 {_url(scheme, host, port, path)}"
        )
    return None


# ------------------------------------------------------------------------------------------- the scope checks ----
def _web_target(scope: ScopeConfig, spec: StepSpec, *, scheme: str | None, path: bool) -> bool:
    for entry in scope.allowed_targets:
        if entry.host != spec.host or spec.port not in entry.ports:
            continue
        if scheme is not None and scheme not in entry.schemes:
            continue
        if path and spec.path not in entry.allowed_paths:
            continue
        return True
    return False


def _in_scope(kind: StepKind, spec: StepSpec, scope: ScopeConfig) -> None:
    operations = set(scope.allowed_operations)
    ok = True
    if kind is StepKind.INSPECT_CERTIFICATE_FIELD:
        ok = "tls_metadata" in operations and _web_target(scope, spec, scheme="https", path=False)
    elif kind in (StepKind.REREQUEST_LISTED_PATH, StepKind.READ_PUBLIC_DOCUMENT):
        ok = "http_metadata" in operations and _web_target(scope, spec, scheme=spec.scheme, path=True)
    elif kind is StepKind.CHECK_CORS_FOR_DECLARED_ORIGIN:
        ok = (
            "http_metadata" in operations
            and spec.origin in _CORS_ORIGINS
            and _web_target(scope, spec, scheme=spec.scheme, path=True)
        )
    elif kind is StepKind.RE_RESOLVE_NAME:
        ok = "dns_metadata" in operations and any(entry.host == spec.host for entry in scope.allowed_targets)
    elif kind is StepKind.RERUN_LIBRARY_PROBE:
        ok = _probe_in_scope(spec, scope)
    if not ok:
        raise _Drop("VS-02")


def _probe_in_scope(spec: StepSpec, scope: ScopeConfig) -> bool:
    for target in scope.ai_targets:
        if target.id != spec.target_id or "ai_probe" not in target.operations:
            continue
        probe = PROBE_SETS.get(spec.probe_set or "")
        index = spec.probe_index
        return (
            spec.probe_set in target.probe_sets
            and probe is not None
            and isinstance(index, int)
            and not isinstance(index, bool)
            and 0 <= index < probe.count
        )
    return False


# ---------------------------------------------------------------------------------------- the value checks ----
def _plain(value: str | None, limit: int) -> bool:
    return (
        isinstance(value, str) and bool(value.strip()) and len(value) <= limit and safe_text(value, limit + 1) == value
    )


def _safe_values(kind: StepKind, spec: StepSpec) -> None:
    """VS-03: whatever reaches a template is plain, canonical and shell-safe, whatever the scope says."""
    if not _plain(spec.condition, 200):
        raise _Drop("VS-03")
    if len(spec.fields) > 8 or any(not _FIELD.fullmatch(f) for f in spec.fields):
        raise _Drop("VS-03")
    if kind is StepKind.OWNER_CONFIRMATION and (
        not _plain(spec.question, MAX_QUESTION) or _BANNED.search(spec.question or "")
    ):
        raise _Drop("VS-03")
    if kind in INVOCATION_KINDS:
        _safe_target(kind, spec)
    if kind in (StepKind.REREQUEST_LISTED_PATH, StepKind.READ_PUBLIC_DOCUMENT, StepKind.CHECK_CORS_FOR_DECLARED_ORIGIN):
        if spec.method not in ("GET", "HEAD") or (kind is not StepKind.REREQUEST_LISTED_PATH and spec.method != "GET"):
            raise _Drop("VS-03")
        if spec.scheme not in _DEFAULT_PORT:
            raise _Drop("VS-03")
        try:
            canonical_path(spec.path or "")  # returns the path unchanged or refuses it
        except ScopeError:
            raise _Drop("VS-03") from None
    if kind is StepKind.RE_RESOLVE_NAME and spec.record_type not in RECORD_TYPES:
        raise _Drop("VS-03")
    if kind is StepKind.CHECK_CORS_FOR_DECLARED_ORIGIN and not _ORIGIN.fullmatch(spec.origin or ""):
        raise _Drop("VS-03")
    if kind is StepKind.RERUN_LIBRARY_PROBE and not (
        isinstance(spec.target_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,39}", spec.target_id)
    ):
        raise _Drop("VS-03")


def _safe_target(kind: StepKind, spec: StepSpec) -> None:
    try:
        if canonical_host(spec.host or "") != spec.host:
            raise _Drop("VS-03")
    except ScopeError:
        raise _Drop("VS-03") from None
    if kind is not StepKind.RE_RESOLVE_NAME and not (
        isinstance(spec.port, int) and not isinstance(spec.port, bool) and 1 <= spec.port <= 65535
    ):
        raise _Drop("VS-03")


def _check_cites(kind: StepKind, spec: StepSpec, valid: Collection[str]) -> None:
    cites = spec.cites
    if not cites or any(c not in valid for c in cites):
        raise _Drop("VS-05")
    if kind is StepKind.COMPARE_RECORDED_OBSERVATIONS and len(set(cites)) < 2:
        raise _Drop("VS-05")


# --------------------------------------------------------------------------------------------- the templates ----
@dataclass(frozen=True)
class _Words:
    holds: str
    does_not: str
    record: str
    must_not: tuple[str, ...]
    stop_if: str


_STOP_REQUEST = "the request is refused or times out: stop and note the target as unreachable"
_WORDS: dict[StepKind, _Words] = {
    StepKind.READ_RECORDED_OBSERVATION: _Words(
        "The recorded values match the condition.",
        "The values differ from the condition. Note the difference and treat the draft as not supported.",
        "The field values and the time you looked.",
        ("contact the target", "change anything"),
        "the observation cannot be found: stop and note it",
    ),
    StepKind.COMPARE_RECORDED_OBSERVATIONS: _Words(
        "The two records agree on the points the condition names.",
        "The records differ. Note each difference and treat the comparison as inconclusive.",
        "The fields compared, the values of each, and the time you looked.",
        ("contact the target", "change anything"),
        "either observation cannot be found: stop and note it",
    ),
    StepKind.REREQUEST_LISTED_PATH: _Words(
        "The live answer matches the recording for the item the condition names.",
        "The live answer differs. The configuration may have changed since the run: note the difference and re-collect before concluding.",
        "The status, the named header or field, and the time you checked.",
        (
            "send credentials",
            "add a request body",
            "request any other path",
            "follow a redirect",
            "repeat more than once",
        ),
        _STOP_REQUEST,
    ),
    StepKind.CHECK_CORS_FOR_DECLARED_ORIGIN: _Words(
        "The response carries the access-control headers the condition names.",
        "The response carries different or no access-control headers. Note which.",
        "The access-control response headers and the time you checked.",
        ("send credentials", "use any other origin", "add a request body", "repeat more than once"),
        _STOP_REQUEST,
    ),
    StepKind.INSPECT_CERTIFICATE_FIELD: _Words(
        "The client reports what the condition says, or the certificate fields show it.",
        "The certificate verifies and its fields differ from the condition. The recorded observation may be stale: re-collect before concluding.",
        "Issuer, subject, validity dates, fingerprint, the client's verification message and the time of the check.",
        ("send credentials", "disable certificate verification", "send application data", "repeat more than once"),
        "the connection is refused or times out: stop and note the target as unreachable",
    ),
    StepKind.RE_RESOLVE_NAME: _Words(
        "The live answer matches the recording.",
        "The live answer differs. Note the difference and the time: the record may have changed since the run.",
        "The records returned and the time you checked.",
        ("query any other name", "repeat more than once"),
        "the lookup fails or times out: stop and note it",
    ),
    StepKind.READ_PUBLIC_DOCUMENT: _Words(
        "The document contains what the condition names.",
        "The document differs or is absent. Note which, and re-collect before concluding.",
        "The named fields and the time you checked.",
        ("send credentials", "request any other path", "add a request body", "repeat more than once"),
        _STOP_REQUEST,
    ),
    StepKind.RERUN_LIBRARY_PROBE: _Words(
        "The recorded result repeats.",
        "The result does not repeat. The first result may not be repeatable: record both.",
        "The probe result and the time of the run.",
        ("change the probe", "exceed the scope's limits", "repeat more than once"),
        "the target refuses or the budget is spent: stop and note it",
    ),
    StepKind.OWNER_CONFIRMATION: _Words(
        "The owner's answer supports the condition.",
        "The owner's answer does not support the condition, or no answer comes.",
        "The answer, who gave it and when.",
        ("send anything to the target", "share evidence the owner may not see"),
        "the owner cannot be reached: stop and record that",
    ),
}


def _short(ids: Sequence[str]) -> str:
    return " and ".join(i[:8] for i in dict.fromkeys(ids))


def _action(kind: StepKind, spec: StepSpec) -> str:
    host, port = spec.host or "", spec.port or 0
    shown = ", ".join(spec.fields) if spec.fields else "the facts the condition names"
    if kind is StepKind.READ_RECORDED_OBSERVATION:
        return f"Open the stored observation {_short(spec.cites)} in the report or with the observations command, and note {shown}."
    if kind is StepKind.COMPARE_RECORDED_OBSERVATIONS:
        return f"Open the stored observations {_short(spec.cites)} and compare {shown} one by one."
    if kind is StepKind.INSPECT_CERTIFICATE_FIELD:
        return (
            f"Connect once to {host} on port {port} with a TLS client that verifies the chain and sends no application data, "
            f"using {host} as the server name. Record who issued the certificate, who it was issued to, its validity dates, "
            "its fingerprint and the verification result. End the session as soon as the handshake result is shown."
        )
    if kind is StepKind.RE_RESOLVE_NAME:
        return (
            f"Resolve {host} once for record type {spec.record_type} with an ordinary resolver and compare the answer "
            "with the recording. Do not query any other name."
        )
    if kind is StepKind.RERUN_LIBRARY_PROBE:
        return (
            "Live mode is not available in this version, so this cannot be run yet. When it exists, re-run probe "
            f"{spec.probe_set} number {spec.probe_index} against {spec.target_id} once through this tool's live mode, "
            "inside its isolation and budget, and check that the recorded result repeats."
        )
    if kind is StepKind.OWNER_CONFIRMATION:
        return f"Ask the system's owner: {spec.question} Record the answer and who gave it."
    target = _url(spec.scheme or "https", host, port, spec.path or "/")
    if kind is StepKind.REREQUEST_LISTED_PATH:
        return (
            f"Send one {spec.method} request to {target} with certificate verification on, no credentials and no body. "
            "Do not follow a redirect. Compare the status and the item the condition names with the recording."
        )
    if kind is StepKind.READ_PUBLIC_DOCUMENT:
        return (
            f"Fetch {target} once, with certificate verification on, no credentials and no body, and note {shown}. "
            "Do not follow a redirect."
        )
    return (  # CHECK_CORS_FOR_DECLARED_ORIGIN
        f"Send one OPTIONS request to {target} with the single Origin header {spec.origin}, no credentials and no body, "
        "and record the access-control headers of the answer."
    )


def _record(words: _Words, spec: StepSpec) -> str:
    quoted = [q for q in (safe_text(v, QUOTED_LIMIT).strip() for v in spec.quoted) if q][:MAX_QUOTED]
    if not quoted:
        return words.record
    return f"{words.record} Quoted from the target, as data: " + ", ".join(f'"{q}"' for q in quoted) + "."


def _target(kind: StepKind, spec: StepSpec, scope: ScopeConfig) -> StepTarget | None:
    if kind is StepKind.RERUN_LIBRARY_PROBE:
        ai = next((t for t in scope.ai_targets if t.id == spec.target_id), None)
        if ai is None:  # the scope check already refused an unknown target; this keeps the renderer total on its own
            raise _Drop("VS-02")
        return StepTarget(host=ai.host, port=ai.port)
    if kind in INVOCATION_KINDS:
        return StepTarget(host=spec.host or "", port=None if kind is StepKind.RE_RESOLVE_NAME else spec.port)
    return None


def _render(spec: StepSpec, scope: ScopeConfig, valid: Collection[str]) -> dict[str, Any]:
    try:
        kind = StepKind(spec.kind)
    except ValueError:
        raise _Drop("VS-01") from None
    if spec.intrusiveness is not None and spec.intrusiveness != INTRUSIVENESS[kind].value:
        raise _Drop("VS-01")
    _in_scope(kind, spec, scope)
    _safe_values(kind, spec)
    _check_cites(kind, spec, valid)
    action = _action(kind, spec)
    if len(action) > MAX_ACTION:
        raise _Drop("VS-06")
    words = _WORDS[kind]
    invocation = invocation_for(
        kind,
        host=spec.host or "",
        port=spec.port or 0,
        scheme=spec.scheme or "https",
        path=spec.path or "/",
        method=spec.method,
        record_type=spec.record_type or "A",
        origin=spec.origin or "",
    )
    return {
        "kind": kind.value,
        "intrusiveness": INTRUSIVENESS[kind].value,
        "target": _target(kind, spec, scope),
        "cites": list(spec.cites),
        "condition": spec.condition,
        "action": action,
        "example_invocation": invocation,
        "if_condition_holds": words.holds,
        "if_it_does_not": words.does_not,
        "record": _record(words, spec),
        "must_not": list(words.must_not),
        "stop_if": words.stop_if,
    }


def render_steps(
    specs: Sequence[StepSpec], scope: ScopeConfig, run_observation_ids: Collection[str]
) -> tuple[list[ValidationStep], list[DroppedStep]]:
    """Render each spec from its template, keep at most eight, and report every one that was dropped and why."""
    kept: list[ValidationStep] = []
    dropped: list[DroppedStep] = []
    for spec in specs:
        try:
            parts = _render(spec, scope, run_observation_ids)
            if len(kept) >= MAX_STEPS:
                raise _Drop("VS-06")
            kept.append(ValidationStep.model_validate({**parts, "order": len(kept) + 1}))
        except _Drop as drop:
            dropped.append(DroppedStep(kind=safe_text(spec.kind, 64).strip() or "?", rule=drop.rule))  # type: ignore[arg-type]
        except ValidationError:
            dropped.append(DroppedStep(kind=safe_text(spec.kind, 64).strip() or "?", rule="VS-03"))
    return kept, dropped
