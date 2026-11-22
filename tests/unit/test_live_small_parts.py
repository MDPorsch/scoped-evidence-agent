"""M6: the leak guard, the rate limiter and the resolver. Small, pure, and each the last line of a security property."""

from __future__ import annotations

import base64
import urllib.parse

import pytest

from scopedagent.live.leakguard import LeakGuard, SecretLeak
from scopedagent.live.ratelimit import RateLimiter
from scopedagent.live.resolver import Resolution, resolve_hosts, system_lookup
from tests.support import assemble

pytestmark = pytest.mark.milestone("M6")

SECRET = assemble("tok_Live-", "SYNTHETIC", "/key+0001==")


# ------------------------------------------------------------------------------------------- leak guard ----
@pytest.mark.parametrize(
    "form",
    [
        SECRET,
        urllib.parse.quote(SECRET, safe=""),
        SECRET.encode().hex(),
        SECRET.encode().hex().upper(),
        base64.b64encode(SECRET.encode()).decode(),
        base64.b64encode(SECRET.encode()).decode().rstrip("="),
        base64.urlsafe_b64encode(SECRET.encode()).decode(),
        base64.b32encode(SECRET.encode()).decode(),
    ],
)
def test_the_secret_is_found_in_every_form_a_target_might_echo_it(form: str) -> None:
    guard = LeakGuard([SECRET])
    for blob in (f"prefix {form} suffix", form, f'{{"echo": "{form}"}}'.encode()):
        with pytest.raises(SecretLeak) as caught:
            guard.check(blob, where="a test")
        assert SECRET not in str(caught.value) and form not in str(caught.value) and "a test" in str(caught.value)


def test_clean_data_passes_and_an_empty_guard_never_objects() -> None:
    LeakGuard([SECRET]).check("nothing to see here, 12345678", where="x")
    assert not LeakGuard([])
    LeakGuard([]).check(SECRET, where="x")  # no secret was promised, so nothing is guarded


def test_a_secret_split_across_two_checks_is_two_clean_checks() -> None:
    guard = LeakGuard([SECRET])
    guard.check(SECRET[:10], where="a")
    guard.check(SECRET[10:], where="b")  # the guard scans each blob it is given: callers give it whole files


def test_several_secrets_are_all_guarded() -> None:
    guard = LeakGuard(["first-secret-value", "second-secret-value"])
    for value in ("first-secret-value", "second-secret-value"):
        with pytest.raises(SecretLeak):
            guard.check(f"x {value} y", where="z")


def test_a_secret_too_short_to_guard_is_refused_up_front() -> None:
    with pytest.raises(ValueError, match="shorter than 8"):
        LeakGuard(["short"])
    assert LeakGuard(["12345678"])


def test_blank_secrets_are_ignored() -> None:
    assert not LeakGuard(["", ""])


# ------------------------------------------------------------------------------------------ rate limiter ----
def test_requests_are_spaced_at_the_configured_rate() -> None:
    now = [100.0]
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    limiter = RateLimiter(2, clock=lambda: now[0], sleep=sleep)
    waits = [limiter.wait() for _ in range(4)]
    assert waits == [0.0, 0.5, 0.5, 0.5] and slept == [0.5, 0.5, 0.5]


def test_time_spent_working_counts_towards_the_gap() -> None:
    now = [0.0]
    limiter = RateLimiter(2, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    limiter.wait()
    now[0] += 0.3  # the request itself took 0.3 s
    assert limiter.wait() == pytest.approx(0.2)
    now[0] += 5.0  # a long pause does not bank up a burst
    assert limiter.wait() == 0.0
    assert limiter.wait() == pytest.approx(0.5)


@pytest.mark.parametrize("rate", [0, 11, -1])
def test_the_rate_is_one_to_ten_per_second(rate: int) -> None:
    with pytest.raises(ValueError, match="1 to 10"):
        RateLimiter(rate)


def test_ten_per_second_is_a_tenth_of_a_second() -> None:
    now = [0.0]
    limiter = RateLimiter(10, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    limiter.wait()
    assert limiter.wait() == pytest.approx(0.1)


# --------------------------------------------------------------------------------------------- resolver ----
def lookup_of(table: dict[str, tuple[list[str], str | None] | Exception]):  # type: ignore[no-untyped-def]
    def lookup(host: str) -> tuple[list[str], str | None]:
        answer = table[host]
        if isinstance(answer, Exception):
            raise answer
        return answer

    return lookup


def test_each_host_is_resolved_once_in_order_and_judged() -> None:
    calls: list[str] = []
    inner = lookup_of(
        {"a.example.invalid": (["8.8.8.8", "1.1.1.1"], None), "b.example.invalid": (["93.184.216.34"], None)}
    )

    def lookup(host: str) -> tuple[list[str], str | None]:
        calls.append(host)
        return inner(host)

    result = resolve_hosts(["a.example.invalid", "b.example.invalid", "a.example.invalid"], [], lookup)
    assert calls == ["a.example.invalid", "b.example.invalid"] and list(result) == calls
    assert result["a.example.invalid"] == Resolution(
        "a.example.invalid", ("8.8.8.8", "1.1.1.1"), None, None, ("8.8.8.8", "1.1.1.1")
    )


def test_a_host_with_one_bad_address_is_refused_whole() -> None:
    result = resolve_hosts(["a.example.invalid"], [], lookup_of({"a.example.invalid": (["8.8.8.8", "10.0.0.5"], None)}))
    refusal = result["a.example.invalid"]
    assert (
        refusal.addresses == ()
        and "10.0.0.5" in str(refusal.refusal)
        and "not a public address" in str(refusal.refusal)
    )


def test_a_private_address_is_accepted_when_the_scope_lists_its_range() -> None:
    result = resolve_hosts(
        ["a.example.invalid"], ["10.20.0.0/16"], lookup_of({"a.example.invalid": (["10.20.1.1"], None)})
    )
    assert result["a.example.invalid"].addresses == ("10.20.1.1",) and result["a.example.invalid"].refusal is None


def test_a_name_that_does_not_resolve_is_not_contacted_and_says_so() -> None:
    result = resolve_hosts(["a.example.invalid"], [], lookup_of({"a.example.invalid": OSError("no such host")}))
    assert (
        result["a.example.invalid"].addresses == ()
        and result["a.example.invalid"].refusal == "the name did not resolve"
    )


def test_a_name_that_resolves_to_nothing_is_refused() -> None:
    result = resolve_hosts(["a.example.invalid"], [], lookup_of({"a.example.invalid": ([], None)}))
    assert "no address" in str(result["a.example.invalid"].refusal)


def test_a_cname_is_kept_as_data_and_never_looked_up() -> None:
    looked: list[str] = []

    def lookup(host: str) -> tuple[list[str], str | None]:
        looked.append(host)
        return ["8.8.8.8"], "cdn.other.example.invalid"

    result = resolve_hosts(["a.example.invalid"], [], lookup)
    assert result["a.example.invalid"].canonical_name == "cdn.other.example.invalid" and looked == ["a.example.invalid"]


def test_the_system_lookup_returns_addresses_and_a_canonical_name_only_when_it_differs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket  # noqa: PLC0415

    infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "cdn.example.invalid", ("93.184.216.34", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800::1", 0, 0, 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: infos)
    assert system_lookup("www.example.invalid") == (["93.184.216.34", "2606:2800::1"], "cdn.example.invalid")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "WWW.example.invalid", ("93.184.216.34", 0))],
    )
    assert system_lookup("www.example.invalid") == (["93.184.216.34"], None)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    assert system_lookup("www.example.invalid") == ([], None)
