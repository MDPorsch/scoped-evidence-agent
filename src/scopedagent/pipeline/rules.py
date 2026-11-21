"""The rule catalogue, version 1 (docs/correlator.md; D-E56 to D-E61).

A rule reads stored observations of one run and the run's scope, and returns drafts. It sends nothing and resolves nothing. Every
sentence it writes is a fixed template filled with a number, a scope-validated host or path, or a quoted target value that matched
a strict shape. A target's text never becomes an instruction, a condition or a title.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from scopedagent.domain.findings import Assessment, SeverityValue, VulnClass
from scopedagent.domain.schemas import PAYLOAD_MODELS
from scopedagent.pipeline.steps import StepSpec
from scopedagent.policy.scope import ScopeConfig

MAX_FACTS = 6
MAX_FACT = 80
MAX_TITLE = 160
MAX_CONDITION = 300
_BANNER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,30}/[0-9][A-Za-z0-9._-]{0,20}( \([A-Za-z0-9_.-]{1,20}\))?")
_PATH_SHAPE = re.compile(r"/[A-Za-z0-9._~/-]{0,60}")
_HOST_SHAPE = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}")
_NAME_SHAPE = re.compile(r"[A-Za-z0-9_.-]{1,40}")
_SENSITIVE_WORDS = ("admin", "backup", "config", ".git", ".env", "internal", "private", "secret", "debug")
_BANNER_HEADERS = (("server", "Server"), ("x-powered-by", "X-Powered-By"), ("x-generator", "X-Generator"))
_SECURITY_HEADERS = (
    ("Strict-Transport-Security", "strict-transport-security", True),
    ("Content-Security-Policy", "content-security-policy", False),
    ("X-Content-Type-Options", "x-content-type-options", False),
)
ASSUMPTION = "The stored observations are an accurate record of what the target answered at the time."
_GUIDE_TAIL = ("The owner cannot say, or the steps cannot be run.", "inconclusive")


@dataclass(frozen=True)
class ObservationView:
    """One stored observation as a rule sees it: its id, kind, outcome, collection time and validated payload."""

    id: str
    type: str
    status: str
    collected_at: datetime
    host: str
    scheme: str
    port: int
    payload: Any

    @classmethod
    def build(
        cls,
        observation_id: str,
        observation_type: str,
        payload: dict[str, Any],
        *,
        target: tuple[str, str, int],
        error_status: str = "ok",
        collected_at: datetime,
    ) -> ObservationView:
        model = PAYLOAD_MODELS[observation_type].model_validate(payload)
        return cls(observation_id, observation_type, error_status, collected_at, *target, model)


@dataclass(frozen=True)
class RuleContext:
    observations: tuple[ObservationView, ...]
    scope: ScopeConfig

    def of(self, observation_type: str) -> list[ObservationView]:
        return [o for o in self.observations if o.type == observation_type and o.status == "ok"]

    @property
    def hosts(self) -> frozenset[str]:
        return frozenset([t.host for t in self.scope.allowed_targets] + [a.host for a in self.scope.ai_targets])


@dataclass(frozen=True)
class RuleDraft:
    rule_id: str
    rule_version: int
    vulnerability_class: VulnClass
    title: str
    confidence: float
    evidence: tuple[str, ...]
    cwe_candidates: tuple[str, ...]
    conditions: tuple[str, ...]
    assessment: Assessment
    preconditions: tuple[str, ...]
    attacker_position: str
    unknowns: tuple[str, ...]
    basis: str
    specs: tuple[StepSpec, ...]
    decision_guide: tuple[tuple[str, str], ...]
    remediation: str
    severity: SeverityValue
    severity_basis: str
    facts: tuple[str, ...]
    assumptions: tuple[str, ...]


@dataclass(frozen=True)
class Rule:
    id: str
    version: int
    vulnerability_class: VulnClass
    run: Callable[[RuleContext], list[RuleDraft]]


# ------------------------------------------------------------------------------------------------ helpers ----
def _plural(count: int, one: str, many: str) -> str:
    return one if count == 1 else many


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cwe(*ids: int) -> tuple[str, ...]:
    return tuple(f"CWE-{i}" for i in sorted(set(ids)))


def _guide(holds: str, not_exploitable: str) -> tuple[tuple[str, str], ...]:
    return ((holds, "confirmed"), (not_exploitable, "not_exploitable"), _GUIDE_TAIL)


def _owner(ids: Sequence[str], question: str, condition: str) -> StepSpec:
    return StepSpec("owner_confirmation", tuple(ids[:1]), condition, question=question)


def _read(ids: Sequence[str], condition: str, fields: tuple[str, ...] = (), quoted: tuple[str, ...] = ()) -> StepSpec:
    return StepSpec("read_recorded_observation", tuple(ids[:1]), condition, fields=fields, quoted=quoted)


def _rerequest(view: ObservationView, condition: str) -> StepSpec:
    payload = view.payload
    return StepSpec(
        "rerequest_listed_path",
        (view.id,),
        condition,
        host=payload.host,
        port=payload.port,
        scheme=payload.scheme,
        path=payload.path,
        method=payload.method,
    )


def _group(views: Iterable[ObservationView], key: Callable[[ObservationView], Any]) -> dict[Any, list[ObservationView]]:
    groups: dict[Any, list[ObservationView]] = defaultdict(list)
    for view in views:
        groups[key(view)].append(view)
    return dict(groups)


def _web_key(view: ObservationView) -> tuple[str, str, int]:
    return (view.payload.host, view.payload.scheme, view.payload.port)


def _headers(view: ObservationView) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = view.payload.headers
    return headers


def _parsed(view: ObservationView) -> dict[str, Any] | None:
    body = view.payload.body
    parsed = body.parsed if body is not None else None
    return parsed if isinstance(parsed, dict) else None


def _fit(value: str, limit: int) -> str:
    """Text cut to a limit, so that a very long host name can never make a draft unstorable."""
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _fact(label: str, value: str, shape: re.Pattern[str]) -> str | None:
    """A quoted target value, only if it has the strict shape AND the finished fact fits: otherwise it is not quoted at all."""
    fact = f"{label}: {value}"
    return fact if shape.fullmatch(value) and len(fact) <= MAX_FACT else None


def _draft(**fields: Any) -> RuleDraft:
    fields.setdefault("assumptions", (ASSUMPTION,))
    fields["title"] = _fit(fields["title"], MAX_TITLE)
    fields["conditions"] = tuple(_fit(c, MAX_CONDITION) for c in fields["conditions"])
    return RuleDraft(**fields)


# ----------------------------------------------------------------------------------------------- R-TLS-01 ----
def _covers(host: str, names: Sequence[str]) -> bool:
    for name in (n.lower() for n in names):
        if name == host or (name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]):
            return True
    return False


def _tls_conditions(view: ObservationView) -> tuple[list[str], set[int], bool]:
    payload = view.payload
    conditions: list[str] = []
    cwe: set[int] = set()
    version_only = False
    if payload.tls_version in ("TLSv1.0", "TLSv1.1"):
        conditions.append(f"The service negotiated {payload.tls_version}, a protocol version that is deprecated.")
        cwe.add(327)
        version_only = True
    cert = payload.certificate
    if cert is None:
        return conditions, cwe, version_only
    if cert.not_after < view.collected_at:
        conditions.append(
            f"The certificate expired on {_stamp(cert.not_after)}, before this observation was collected."
        )
        cwe.add(295)
    if cert.not_before > view.collected_at:
        conditions.append(
            f"The certificate is not valid until {_stamp(cert.not_before)}, after this observation was collected."
        )
        cwe.add(295)
    if cert.self_signed:
        conditions.append("The certificate is self-signed, so it cannot be chained to a trusted authority.")
        cwe.add(295)
    key, bits = cert.public_key.type, cert.public_key.bits
    if key == "rsa" and bits is not None and bits < 2048:
        conditions.append(f"The certificate's RSA key is {bits} bits, shorter than the 2048 bits generally expected.")
        cwe.add(326)
    elif key == "dsa":
        conditions.append("The certificate's key is a DSA key, a type that is deprecated.")
        cwe.add(326)
    elif key == "ec" and bits is not None and bits < 224:
        conditions.append(f"The certificate's EC key is {bits} bits, shorter than the 224 bits generally expected.")
        cwe.add(326)
    algorithm = cert.signature_algorithm.lower()
    if "sha1" in algorithm or "md5" in algorithm:
        conditions.append("The certificate's signature algorithm uses SHA-1 or MD5, which are considered weak.")
        cwe.add(327)
    if not _covers(payload.host, cert.san_dns or [cert.subject_cn]):
        conditions.append(f"The certificate's names do not cover {payload.host}.")
        cwe.add(295)
    return conditions, cwe, version_only and len(conditions) == 1


def _tls_rule(ctx: RuleContext) -> list[RuleDraft]:
    drafts = []
    for view in ctx.of("tls_metadata"):
        if view.payload.status != "ok":
            continue
        conditions, cwe, version_only = _tls_conditions(view)
        if not conditions:
            continue
        payload = view.payload
        drafts.append(
            _draft(
                rule_id="R-TLS-01",
                rule_version=1,
                vulnerability_class=VulnClass.TLS_MISCONFIGURATION,
                title=f"TLS configuration weaknesses on {payload.host}:{payload.port}",
                confidence=0.8 if version_only else 0.9,
                evidence=(view.id,),
                cwe_candidates=_cwe(*cwe),
                conditions=tuple(conditions),
                assessment=Assessment.CONDITIONAL,
                preconditions=(
                    "A client that does not verify the certificate, or that can be downgraded to the weaker protocol, connects to this service.",
                    "An attacker can present their own certificate or alter the connection.",
                ),
                attacker_position="On the network path between a client and the service.",
                unknowns=(
                    "Whether any client of this service verifies certificates or pins this one.",
                    "Whether this is the certificate real users are shown, or a default on an internal service.",
                ),
                basis="Rule R-TLS-01: weaknesses were observed in the presented certificate and protocol. Nothing was exploited.",
                specs=(
                    _read(
                        (view.id,),
                        "the recorded protocol and certificate facts are as listed",
                        ("tls_version", "not_before", "not_after", "self_signed", "public_key"),
                    ),
                    StepSpec(
                        "inspect_certificate_field",
                        (view.id,),
                        "the service presents the certificate and protocol that were recorded",
                        host=payload.host,
                        port=payload.port,
                    ),
                    _owner(
                        (view.id,),
                        "Is this service in use, and does any client pin this certificate?",
                        "the weakness matters to a real client",
                    ),
                ),
                decision_guide=_guide(
                    "The service is in use and a client does not verify the certificate: the weakness is real here.",
                    "The host is decommissioned or only verifying clients use it.",
                ),
                remediation="Present a certificate from a trusted authority that covers the host name, is in date and uses a strong key and signature, and disable legacy protocol versions.",
                severity=SeverityValue.MEDIUM if len(conditions) >= 3 else SeverityValue.LOW,
                severity_basis=f"{len(conditions)} weakness{_plural(len(conditions), '', 'es')} observed, each depending on what the client does.",
                facts=(),
            )
        )
    return drafts


# ----------------------------------------------------------------------------------------------- R-HDR-01 ----
def _count_phrase(n: int) -> str:
    return "the only collected response" if n == 1 else f"all {n} collected responses"


def _hdr_rule(ctx: RuleContext) -> list[RuleDraft]:
    drafts = []
    pages = [
        v for v in ctx.of("http_metadata") if v.payload.http_status is not None and 200 <= v.payload.http_status <= 399
    ]
    for (host, scheme, port), views in _group(pages, _web_key).items():
        missing = [
            name
            for name, header, https_only in _SECURITY_HEADERS
            if (scheme == "https" or not https_only) and not any(_headers(v).get(header) for v in views)
        ]
        if not missing:
            continue
        hsts = "Strict-Transport-Security" in missing
        ids = tuple(v.id for v in views)
        drafts.append(
            _draft(
                rule_id="R-HDR-01",
                rule_version=1,
                vulnerability_class=VulnClass.MISSING_SECURITY_HEADER,
                title=f"Missing security headers on {host}:{port}",
                confidence=0.7,
                evidence=ids,
                cwe_candidates=_cwe(693, *([319] if hsts else [])),
                conditions=tuple(
                    f"{name} was absent from {_count_phrase(len(views))} of this target." for name in missing
                ),
                assessment=Assessment.CONDITIONAL if hsts else Assessment.UNLIKELY,
                preconditions=(
                    "A browser or client that relies on these headers for protection visits the service.",
                    "For a missing transport policy, an attacker can intercept a first plain-text request.",
                ),
                attacker_position="On the network path, or able to get a victim to open content from the service.",
                unknowns=(
                    "Paths that were not collected may send these headers.",
                    "Whether a front end adds them for browsers is not shown.",
                ),
                basis="Rule R-HDR-01: the headers were absent from every collected response of this target. Absence elsewhere is not shown.",
                specs=(
                    _read(ids, "the recorded responses lack the headers", ("headers", "http_status")),
                    _rerequest(views[0], "the header is still absent from a live response"),
                    _owner(
                        ids,
                        "Is plain HTTP served at all, and does a redirect to HTTPS or a preload entry exist?",
                        "the missing header can be exploited in practice",
                    ),
                ),
                decision_guide=_guide(
                    "The header is absent and plain HTTP is served: the downgrade condition holds.",
                    "Only HTTPS is served, with a preload entry or an equivalent control.",
                ),
                remediation="Send Strict-Transport-Security over HTTPS, and add Content-Security-Policy and X-Content-Type-Options to responses.",
                severity=SeverityValue.LOW if hsts else SeverityValue.INFO,
                severity_basis="Hardening headers are absent. Impact depends on how the service is reached.",
                facts=(),
            )
        )
    return drafts


# ---------------------------------------------------------------------------------------------- R-INFO-01 ----
def _info_banner_rule(ctx: RuleContext) -> list[RuleDraft]:
    drafts = []
    for (host, _scheme, port), views in _group(ctx.of("http_metadata"), _web_key).items():
        found: dict[str, list[str]] = {header: [] for header, _ in _BANNER_HEADERS}
        evidence: list[ObservationView] = []
        for view in views:
            hit = False
            for header, _ in _BANNER_HEADERS:
                for value in _headers(view).get(header, []):
                    if _BANNER.fullmatch(value):
                        hit = True
                        if value not in found[header]:
                            found[header].append(value)
            if hit:
                evidence.append(view)
        if not evidence:
            continue
        facts = tuple(
            fact
            for header, label in _BANNER_HEADERS
            for value in found[header]
            if (fact := _fact(label, value, _BANNER))
        )[:MAX_FACTS]
        ids = tuple(v.id for v in evidence)
        first = (
            StepSpec(
                "compare_recorded_observations",
                ids[:8],
                "the banner is consistent across responses",
                fields=("server", "x-powered-by"),
                quoted=facts[:3],
            )
            if len(ids) > 1
            else _read(ids, "the recorded banner is as listed", ("server", "x-powered-by"), facts[:3])
        )
        drafts.append(
            _draft(
                rule_id="R-INFO-01",
                rule_version=1,
                vulnerability_class=VulnClass.INFORMATION_DISCLOSURE,
                title=f"Software version disclosed by {host}:{port}",
                confidence=0.8,
                evidence=ids,
                cwe_candidates=_cwe(200),
                conditions=tuple(
                    f"Responses name the software and its version in the {label} header."
                    for header, label in _BANNER_HEADERS
                    if found[header]
                ),
                assessment=Assessment.UNLIKELY,
                preconditions=("Someone can read the response headers of the service.",),
                attacker_position="Any client that can reach the service.",
                unknowns=(
                    "Whether the banner is the real deployed version or is set by a front end.",
                    "Whether that version is still supported. This tool does not map a version to known weaknesses.",
                ),
                basis="Rule R-INFO-01: a response header names a product and a version. Disclosure alone gives no access.",
                specs=(
                    first,
                    _owner(
                        ids,
                        "Which software and version is really deployed, and is the banner overridden by a front end?",
                        "the banner reflects the deployed software",
                    ),
                ),
                decision_guide=_guide(
                    "The banner is accurate and the version is outdated or unsupported.",
                    "The banner is overridden or the version is current.",
                ),
                remediation="Remove or generalise version details from response headers, and keep the software supported and patched.",
                severity=SeverityValue.INFO,
                severity_basis="Information disclosure that helps a person plan, with no access by itself.",
                facts=facts,
            )
        )
    return drafts


# ---------------------------------------------------------------------------------------------- R-INFO-02 ----
def _info_robots_rule(ctx: RuleContext) -> list[RuleDraft]:
    drafts = []
    for (host, _scheme, port), views in _group(ctx.of("http_metadata"), _web_key).items():
        count, facts, evidence = 0, [], []
        for view in views:
            parsed = _parsed(view)
            listed = parsed.get("disallow") if parsed else None
            if not isinstance(listed, list):
                continue
            sensitive = [p for p in listed if isinstance(p, str) and any(w in p.lower() for w in _SENSITIVE_WORDS)]
            if not sensitive:
                continue
            count += len(sensitive)
            evidence.append(view)
            for path in sensitive:
                fact = _fact("Disallow", path, _PATH_SHAPE)
                if fact is not None and fact not in facts:
                    facts.append(fact)
        if not evidence:
            continue
        ids = tuple(v.id for v in evidence)
        sentence = f"robots.txt asks crawlers to skip {count} {_plural(count, 'path whose name suggests', 'paths whose names suggest')} sensitive content."
        drafts.append(
            _draft(
                rule_id="R-INFO-02",
                rule_version=1,
                vulnerability_class=VulnClass.INFORMATION_DISCLOSURE,
                title=f"Sensitive-looking paths listed in robots.txt on {host}:{port}",
                confidence=0.6,
                evidence=ids,
                cwe_candidates=_cwe(200),
                conditions=(sentence,),
                assessment=Assessment.UNLIKELY,
                preconditions=("The listed paths exist and are reachable without further protection.",),
                attacker_position="Any client that can read robots.txt.",
                unknowns=(
                    "Whether the listed paths exist or require authentication.",
                    "The tool did not request any listed path: they are outside what the scope lists.",
                ),
                basis="Rule R-INFO-02: robots.txt names paths whose names suggest sensitive content. Listing a path is not a flaw in the path.",
                specs=(
                    _read(ids, "robots.txt lists the paths quoted in the draft", ("disallow",), tuple(facts[:3])),
                    _owner(
                        ids,
                        "Are the listed paths meant to be hidden, and are they protected by authentication?",
                        "a listed path is exposed",
                    ),
                ),
                decision_guide=_guide(
                    "A listed path is reachable without authentication and holds sensitive content.",
                    "The paths are protected or hold nothing sensitive.",
                ),
                remediation="Protect sensitive paths with authentication rather than listing them in robots.txt, and remove entries that only advertise them.",
                severity=SeverityValue.INFO,
                severity_basis="Advertises where to look. No access is shown.",
                facts=tuple(facts[:MAX_FACTS]),
            )
        )
    return drafts


# --------------------------------------------------------------------------------------------- R-REDIR-01 ----
def _redirect_host(location: str | None) -> tuple[str | None, str]:
    if not location:
        return None, ""
    try:
        parts = urlsplit(location)
        return parts.hostname, parts.scheme  # urlsplit lower-cases the scheme
    except ValueError:
        return None, ""


def _redir_rule(ctx: RuleContext) -> list[RuleDraft]:
    drafts = []
    for (host, _scheme, port), views in _group(ctx.of("http_metadata"), _web_key).items():
        evidence: list[ObservationView] = []
        plain = outside = False
        facts: list[str] = []
        for view in views:
            target, scheme = _redirect_host(view.payload.redirect_location)
            if target is None:
                continue
            is_plain, is_outside = scheme == "http", target not in ctx.hosts
            if not (is_plain or is_outside):
                continue
            evidence.append(view)
            plain, outside = plain or is_plain, outside or is_outside
            fact = _fact("Location host", target, _HOST_SHAPE)
            if fact is not None and fact not in facts:
                facts.append(fact)
        if not evidence:
            continue
        ids = tuple(v.id for v in evidence)
        conditions = []
        if plain:
            conditions.append("The response redirects to an address that is not encrypted (http).")
        if outside:
            conditions.append(
                "The redirect target's host is not one the scope lists; it was recorded and not followed."
            )
        drafts.append(
            _draft(
                rule_id="R-REDIR-01",
                rule_version=1,
                vulnerability_class=VulnClass.INSECURE_REDIRECT,
                title=f"Insecure or external redirect on {host}:{port}",
                confidence=0.85,
                evidence=ids,
                cwe_candidates=_cwe(*([319] if plain else []), *([610] if outside else [])),
                conditions=tuple(conditions),
                assessment=Assessment.CONDITIONAL,
                preconditions=("A client follows the redirect without checking where it leads.",),
                attacker_position="On the network path for an unencrypted redirect, or controlling the redirect target.",
                unknowns=(
                    "Whether the redirect is intended, for example a migration or a local test left in place.",
                    "What the target of the redirect serves: the tool never followed it.",
                ),
                basis="Rule R-REDIR-01: the response redirects to an unencrypted or out-of-scope address. The redirect was recorded, not followed.",
                specs=(
                    _read(
                        ids,
                        "the recorded redirect target is as listed",
                        ("redirect_location", "http_status"),
                        tuple(facts[:3]),
                    ),
                    _rerequest(evidence[0], "the response still redirects to the same place"),
                    _owner(
                        ids,
                        "Is this redirect intended, and where should it lead?",
                        "the redirect is a flaw rather than a design",
                    ),
                ),
                decision_guide=_guide(
                    "The redirect is unintended and leads off the service or over plain HTTP.",
                    "The redirect is intended and safe.",
                ),
                remediation="Redirect only to HTTPS addresses the service owns, and remove redirects to local or development addresses.",
                severity=SeverityValue.LOW,
                severity_basis="A redirect that leaves encryption or the service. Impact depends on the client.",
                facts=tuple(facts[:MAX_FACTS]),
            )
        )
    return drafts


# ----------------------------------------------------------------------------------------------- R-API-01 ----
def _server_hosts(parsed: dict[str, Any], own: str) -> list[str]:
    urls = parsed.get("server_urls")
    found: list[str] = []
    for url in urls if isinstance(urls, list) else []:
        if not isinstance(url, str):
            continue
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        if host and host != own and host not in found:  # `own` is a canonical (lower-case) payload host
            found.append(host)
    return found


def _api_rule(ctx: RuleContext) -> list[RuleDraft]:
    drafts = []
    for (host, _scheme, port), views in _group(ctx.of("http_metadata"), _web_key).items():
        evidence = []
        for view in views:
            parsed = _parsed(view)
            if parsed is not None and "openapi" in parsed and _server_hosts(parsed, host):
                evidence.append((view, parsed))
        if not evidence:
            continue
        view, parsed = evidence[0]
        others = _server_hosts(parsed, host)
        paths = parsed.get("path_count")
        count = paths if isinstance(paths, int) and not isinstance(paths, bool) else 0
        schemes = parsed.get("security_schemes")
        facts = [fact for h in others if (fact := _fact("Server host", h, _HOST_SHAPE))]
        facts += [
            fact
            for s in (schemes if isinstance(schemes, list) else [])
            if isinstance(s, str) and (fact := _fact("Security scheme", s, _NAME_SHAPE))
        ]
        ids = tuple(v.id for v, _ in evidence)
        drafts.append(
            _draft(
                rule_id="R-API-01",
                rule_version=1,
                vulnerability_class=VulnClass.EXPOSED_API_DOCUMENTATION,
                title=f"Exposed API description on {host}:{port}",
                confidence=0.75,
                evidence=ids,
                cwe_candidates=_cwe(200),
                conditions=(
                    f"The API description at {view.payload.path} was served to an anonymous request.",
                    f"It describes {count} {_plural(count, 'path', 'paths')}.",
                    f"It names {len(others)} server {_plural(len(others), 'host', 'hosts')} other than this target's own.",
                ),
                assessment=Assessment.CONDITIONAL,
                preconditions=("The described endpoints or the named hosts are reachable by an attacker.",),
                attacker_position="Any client that can reach the service.",
                unknowns=(
                    "Whether the named hosts are internal, in use or reachable.",
                    "The tool did not contact any named host: they are outside what the scope lists.",
                ),
                basis="Rule R-API-01: an API description is public and names hosts other than the target's own. The description was read as data only.",
                specs=(
                    _read(
                        ids,
                        "the recorded description names the hosts quoted in the draft",
                        ("openapi", "path_count"),
                        tuple(facts[:3]),
                    ),
                    _rerequest(view, "the description is still served to an anonymous request"),
                    _owner(
                        ids,
                        "Is this API description meant to be public, and are the named hosts in use?",
                        "the description exposes more than intended",
                    ),
                ),
                decision_guide=_guide(
                    "The description is not meant to be public or names internal hosts.",
                    "The description is public by design and names nothing sensitive.",
                ),
                remediation="Serve API descriptions only to the people who need them, and keep internal host names out of public documents.",
                severity=SeverityValue.LOW,
                severity_basis="Documentation that maps the surface and names other hosts. No access is shown.",
                facts=tuple(facts[:MAX_FACTS]),
            )
        )
    return drafts


# ----------------------------------------------------------------------------------------------- R-CORS-01 ----
def _cors_origin(view: ObservationView) -> str | None:
    for value in _headers(view).get("access-control-allow-origin", []):
        shown = value.strip().lower()
        if shown in ("*", "null"):
            return shown
    return None


def _cors_credentials(view: ObservationView) -> bool:
    return any(v.strip().lower() == "true" for v in _headers(view).get("access-control-allow-credentials", []))


def _cors_rule(ctx: RuleContext) -> list[RuleDraft]:
    drafts = []
    for (host, _scheme, port), views in _group(ctx.of("http_metadata"), _web_key).items():
        evidence = [v for v in views if _cors_origin(v) is not None]
        if not evidence:
            continue
        shown = {_cors_origin(v) for v in evidence}
        credentials = any(_cors_credentials(v) for v in evidence)
        conditions = []
        if "*" in shown:
            conditions.append(
                "The response sets Access-Control-Allow-Origin to *, so scripts on any website may read it."
            )
        if "null" in shown:
            conditions.append(
                "The response sets Access-Control-Allow-Origin to null, which sandboxed pages and local files can match."
            )
        if credentials:
            conditions.append("It also sets Access-Control-Allow-Credentials to true.")
        ids = tuple(v.id for v in evidence)
        drafts.append(
            _draft(
                rule_id="R-CORS-01",
                rule_version=1,
                vulnerability_class=VulnClass.PERMISSIVE_CORS,
                title=f"Permissive CORS policy on {host}:{port}",
                confidence=0.7,
                evidence=ids,
                cwe_candidates=_cwe(942),
                conditions=tuple(conditions),
                assessment=Assessment.CONDITIONAL if credentials else Assessment.UNLIKELY,
                preconditions=("The response holds data that is not meant to be read by other websites.",),
                attacker_position="A website the victim visits while able to reach the service.",
                unknowns=(
                    "Whether the response holds anything not already public.",
                    "Whether credentials or cookies would be sent with a cross-origin request.",
                ),
                basis="Rule R-CORS-01: the response allows any or a null origin. This matters only if the content is not public.",
                specs=(
                    _read(ids, "the recorded access-control header is as listed", ("headers",)),
                    _rerequest(evidence[0], "the access-control header is still set"),
                    _owner(
                        ids,
                        "Is the content of this response public, and does it ever depend on a login?",
                        "the policy exposes non-public data",
                    ),
                ),
                decision_guide=_guide(
                    "The response holds non-public data or depends on a login.",
                    "The content is public.",
                ),
                remediation="Allow only the specific origins that need access, and never allow credentials with a wildcard.",
                severity=SeverityValue.MEDIUM if credentials else SeverityValue.LOW,
                severity_basis="A permissive cross-origin policy. Impact depends on what the response holds.",
                facts=(),
            )
        )
    return drafts


# ------------------------------------------------------------------------------------------------ R-DNS-01 ----
def _dns_rule(ctx: RuleContext) -> list[RuleDraft]:
    drafts = []
    for view in ctx.of("dns_metadata"):
        names = [n.strip().rstrip(".").lower() for n in view.payload.records.get("CNAME", [])]
        outside = [n for n in names if n not in ctx.hosts and not any(n.endswith("." + h) for h in ctx.hosts)]
        if not outside:
            continue
        host = view.payload.host
        facts = tuple(dict.fromkeys(f for n in outside if (f := _fact("CNAME", n, _HOST_SHAPE))))[:MAX_FACTS]
        drafts.append(
            _draft(
                rule_id="R-DNS-01",
                rule_version=1,
                vulnerability_class=VulnClass.DNS_EXTERNAL_REFERENCE,
                title=f"DNS alias points outside the scope for {host}",
                confidence=0.5,
                evidence=(view.id,),
                cwe_candidates=(),
                conditions=("A CNAME record points to a name outside the hosts the scope lists.",),
                assessment=Assessment.NOT_ASSESSED,
                preconditions=("The name the alias points to is unregistered, expired or controlled by someone else.",),
                attacker_position="Able to register or control the name the alias points to.",
                unknowns=(
                    "Whether the name outside the scope still resolves or belongs to the owner. The tool will not resolve a name outside the scope.",
                    "Whether the alias is an intended third-party service such as a content network.",
                ),
                basis="Rule R-DNS-01: an alias points outside the listed hosts. Judging it needs a lookup the scope does not allow, so it is not assessed.",
                specs=(
                    _read((view.id,), "the recorded alias is as listed", ("records",), facts[:3]),
                    StepSpec(
                        "re_resolve_name", (view.id,), "the alias is still published", host=host, record_type="CNAME"
                    ),
                    _owner(
                        (view.id,),
                        "Does the organisation own and use the name this alias points to?",
                        "the alias points at something not controlled by the owner",
                    ),
                ),
                decision_guide=_guide(
                    "The target name is not owned or not in use: the alias is a takeover risk.",
                    "The target name is an intended service the owner controls.",
                ),
                remediation="Remove aliases that point at names the organisation no longer controls, and review third-party aliases regularly.",
                severity=SeverityValue.INFO,
                severity_basis="An alias to an outside name. Risk exists only if that name is claimable.",
                facts=facts,
            )
        )
    return drafts


# ---------------------------------------------------------------------------------------------- R-AI-01..04 ----
def _probes(ctx: RuleContext, category: str) -> list[ObservationView]:
    return [v for v in ctx.of("ai_probe") if v.payload.category == category]


def _probe_noun(n: int) -> str:
    return _plural(n, "probe", "probes")


def _ai_spec(view: ObservationView) -> StepSpec:
    payload = view.payload
    return StepSpec(
        "rerun_library_probe",
        (view.id,),
        "the recorded probe result repeats",
        target_id=payload.ai_target_id,
        probe_set=payload.probe_set,
        probe_index=payload.probe_index,
    )


def _canary_rule(
    rule_id: str,
    cls: VulnClass,
    category: str,
    title: str,
    cwe: tuple[str, ...],
    attacker: str,
    remediation: str,
    basis: str,
) -> Callable[[RuleContext], list[RuleDraft]]:
    def run(ctx: RuleContext) -> list[RuleDraft]:
        drafts = []
        probes = _probes(ctx, category)
        for target_id, views in _group(probes, lambda v: v.payload.ai_target_id).items():
            firing = [v for v in views if v.payload.canary_present is True]
            if not firing:
                continue
            totals = _group(views, lambda v: v.payload.probe_set)
            sets = list(dict.fromkeys(v.payload.probe_set for v in firing))
            conditions = tuple(
                f"The planted canary appeared in the reply to "
                f"{sum(1 for v in totals[s] if v.payload.canary_present is True)} of {len(totals[s])} "
                f"{_probe_noun(len(totals[s]))} in set {s}."
                for s in sets
            )
            ids = tuple(v.id for v in firing)
            drafts.append(
                _draft(
                    rule_id=rule_id,
                    rule_version=1,
                    vulnerability_class=cls,
                    title=title.format(target=target_id),
                    confidence=0.6,
                    evidence=ids,
                    cwe_candidates=cwe,
                    conditions=conditions,
                    assessment=Assessment.CONDITIONAL,
                    preconditions=(
                        "An attacker can place text where the model reads it, or talk to the model directly.",
                        "The deployment gives the model something worth leaking or acting on.",
                    ),
                    attacker_position=attacker,
                    unknowns=(
                        "Whether the result repeats: each probe was run once.",
                        "Whether the deployment gives the model tools or private data. A canary shows behaviour, not impact.",
                    ),
                    basis=basis,
                    specs=(
                        _read(ids, "the recorded probe result is as listed", ("canary_present", "finish_reason")),
                        _ai_spec(firing[0]),
                        _owner(
                            ids,
                            "How are the system prompt and retrieved content kept apart, and does this deployment give the model any tools?",
                            "the behaviour has impact in this deployment",
                        ),
                    ),
                    decision_guide=_guide(
                        "The result repeats and the deployment gives the model tools or private data.",
                        "The result does not repeat, or the model has no tools and no sensitive data.",
                    ),
                    remediation=remediation,
                    severity=SeverityValue.MEDIUM,
                    severity_basis="A planted canary was reproduced. Real impact depends on the deployment.",
                    facts=(),
                )
            )
        return drafts

    return run


_FLAGS = (
    ("contains_html", "HTML markup"),
    ("contains_markdown_link", "a Markdown link"),
    ("contains_code_block", "a code block"),
    ("contains_url", "a URL"),
)


def _flagged(view: ObservationView, flag: str) -> bool:
    flags = view.payload.flags
    return flags is not None and bool(getattr(flags, flag))


def _output_rule(ctx: RuleContext) -> list[RuleDraft]:
    drafts = []
    for target_id, views in _group(_probes(ctx, "output_handling"), lambda v: v.payload.ai_target_id).items():
        firing = [v for v in views if any(_flagged(v, flag) for flag, _ in _FLAGS)]
        if not firing:
            continue
        totals = _group(views, lambda v: v.payload.probe_set)
        conditions = []
        for probe_set in dict.fromkeys(v.payload.probe_set for v in firing):
            for flag, what in _FLAGS:
                hits = sum(1 for v in totals[probe_set] if _flagged(v, flag))
                if hits:
                    n = len(totals[probe_set])
                    conditions.append(
                        f"The reply to {hits} of {n} {_probe_noun(n)} in set {probe_set} contained {what}."
                    )
        ids = tuple(v.id for v in firing)
        drafts.append(
            _draft(
                rule_id="R-AI-04",
                rule_version=1,
                vulnerability_class=VulnClass.AI_OUTPUT_HANDLING,
                title=f"Structured content in AI replies from {target_id}",
                confidence=0.7,
                evidence=ids,
                cwe_candidates=_cwe(116),
                conditions=tuple(conditions),
                assessment=Assessment.CONDITIONAL,
                preconditions=("A client renders or acts on the model's reply without escaping it.",),
                attacker_position="Able to influence what the model writes, for example through content it reads.",
                unknowns=(
                    "Whether the client escapes the reply before showing it.",
                    "Whether the structure was caused by the probe text or appears in ordinary replies.",
                ),
                basis="Rule R-AI-04: replies contained markup, links, code or addresses. Whether that is dangerous depends on the client.",
                specs=(
                    _read(ids, "the recorded reply structure is as listed", ("flags", "finish_reason")),
                    _ai_spec(firing[0]),
                    _owner(
                        ids,
                        "Does the application render the reply as HTML or Markdown, and does it follow links or run code from it?",
                        "the client acts on the structure",
                    ),
                ),
                decision_guide=_guide(
                    "The client renders or acts on the structure without escaping it.",
                    "The client shows the reply as plain text.",
                ),
                remediation="Treat model output as untrusted: escape it for the place it is shown and never run or follow what it contains.",
                severity=SeverityValue.LOW,
                severity_basis="Structure in a reply. Impact depends on how the client uses it.",
                facts=(),
            )
        )
    return drafts


_CANARY_RULES = (
    _canary_rule(
        "R-AI-01",
        VulnClass.AI_PROMPT_INJECTION_SUSCEPTIBILITY,
        "prompt_injection",
        "Prompt-injection susceptibility signal on {target}",
        _cwe(1427),
        "Able to put text in front of the model, for example in a document it reads.",
        "Keep instructions and untrusted content apart, limit what the model can do, and check its output before acting on it.",
        "Rule R-AI-01: a planted canary was repeated back. This shows the model followed or echoed untrusted text, not that harm resulted.",
    ),
    _canary_rule(
        "R-AI-02",
        VulnClass.AI_SYSTEM_PROMPT_LEAKAGE,
        "system_prompt_leakage",
        "System-prompt leakage signal on {target}",
        _cwe(200),
        "Able to talk to the model.",
        "Keep secrets out of system prompts and do not rely on a prompt to protect them.",
        "Rule R-AI-02: a canary placed in hidden configuration was reproduced. This shows leakage of that text, not of anything real.",
    ),
    _canary_rule(
        "R-AI-03",
        VulnClass.AI_SENSITIVE_INFORMATION_DISCLOSURE,
        "sensitive_information_disclosure",
        "Sensitive-data disclosure signal on {target}",
        _cwe(200),
        "Able to talk to the model.",
        "Keep sensitive data out of what the model can read, and enforce access control outside the model.",
        "Rule R-AI-03: data seeded for the test was returned. This shows the model can return seeded data, not that real data is exposed.",
    ),
)


def _rule(id_: str, cls: VulnClass, run: Callable[[RuleContext], list[RuleDraft]]) -> Rule:
    return Rule(id_, 1, cls, run)


RULES: tuple[Rule, ...] = (
    _rule("R-TLS-01", VulnClass.TLS_MISCONFIGURATION, _tls_rule),
    _rule("R-HDR-01", VulnClass.MISSING_SECURITY_HEADER, _hdr_rule),
    _rule("R-INFO-01", VulnClass.INFORMATION_DISCLOSURE, _info_banner_rule),
    _rule("R-INFO-02", VulnClass.INFORMATION_DISCLOSURE, _info_robots_rule),
    _rule("R-REDIR-01", VulnClass.INSECURE_REDIRECT, _redir_rule),
    _rule("R-API-01", VulnClass.EXPOSED_API_DOCUMENTATION, _api_rule),
    _rule("R-CORS-01", VulnClass.PERMISSIVE_CORS, _cors_rule),
    _rule("R-DNS-01", VulnClass.DNS_EXTERNAL_REFERENCE, _dns_rule),
    _rule("R-AI-01", VulnClass.AI_PROMPT_INJECTION_SUSCEPTIBILITY, _CANARY_RULES[0]),
    _rule("R-AI-02", VulnClass.AI_SYSTEM_PROMPT_LEAKAGE, _CANARY_RULES[1]),
    _rule("R-AI-03", VulnClass.AI_SENSITIVE_INFORMATION_DISCLOSURE, _CANARY_RULES[2]),
    _rule("R-AI-04", VulnClass.AI_OUTPUT_HANDLING, _output_rule),
)


def run_rules(context: RuleContext) -> list[RuleDraft]:
    """Every rule in catalogue order; within a rule, in the order of the first observation each draft cites."""
    drafts: list[RuleDraft] = []
    for rule in RULES:
        drafts.extend(rule.run(context))
    return drafts
