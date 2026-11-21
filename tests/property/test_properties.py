"""Hypothesis properties. Hypothesis searches; it does not cover. Explicit examples sit beside each property."""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml
from hypothesis import example, given, settings
from hypothesis import strategies as st

from scopedagent.domain.state_machine import (
    Actor,
    ActorType,
    FindingStatus,
    RunState,
    check_finding_transition,
    check_run_transition,
)
from scopedagent.errors import ScopedAgentError, ScopeError, StateError
from scopedagent.policy.scope import canonical_host, canonical_path, parse_scope
from tests.support import NOW, dump, scope_dict

pytestmark = pytest.mark.milestone("M1")

HOSTISH = st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x2FFF), max_size=80)
LABELS = st.from_regex(r"[A-Za-z0-9]([A-Za-z0-9-]{0,10}[A-Za-z0-9])?", fullmatch=True)


@given(HOSTISH)
@example("LAB.example.invalid.")
@example("xn--bcher-kva.example.invalid")
def test_canonical_host_either_refuses_or_returns_a_fixed_point_with_a_safe_alphabet(raw: str) -> None:
    try:
        host = canonical_host(raw)
    except ScopeError:
        return
    assert canonical_host(host) == host  # canonicalizing twice changes nothing
    assert host == host.lower() and not host.endswith(".") and len(host.split(".")) > 1 and len(host) <= 253
    assert all(c in "abcdefghijklmnopqrstuvwxyz0123456789-." for c in host)
    assert not host.split(".")[-1].isdigit()


@given(st.lists(LABELS, min_size=2, max_size=6))
def test_every_well_formed_name_is_accepted_and_lowered(labels: list[str]) -> None:
    raw = ".".join(labels)
    if labels[-1].isdigit():
        with pytest.raises(ScopeError):
            canonical_host(raw)
    else:
        assert canonical_host(raw) == raw.lower()


@given(st.text(max_size=80))
@example("/a/../b")
@example("/robots.txt")
def test_canonical_path_either_refuses_or_returns_the_input_unchanged_with_a_safe_alphabet(raw: str) -> None:
    try:
        path = canonical_path(raw)
    except ScopeError:
        return
    assert path == raw and path.startswith("/") and len(path) <= 256
    assert all(c.isascii() and (c.isalnum() or c in "/._~-") for c in path)
    assert "//" not in path and not {".", ".."} & set(path.split("/"))


@given(st.permutations(list(scope_dict().items())))
def test_the_scope_hash_does_not_depend_on_key_order(items: list[tuple[str, Any]]) -> None:
    baseline = parse_scope(dump(scope_dict()), now=NOW).sha256
    assert parse_scope(dump(dict(items)), now=NOW).sha256 == baseline


@given(
    host=LABELS.map(lambda s: s + ".example.invalid"),
    port=st.integers(min_value=1, max_value=65535),
    paths=st.lists(st.from_regex(r"/[a-z]{1,8}", fullmatch=True), max_size=5, unique=True),
    budget=st.integers(min_value=1, max_value=500),
)
def test_a_generated_valid_scope_always_parses_and_its_plan_matches_its_contents(
    host: str, port: int, paths: list[str], budget: int
) -> None:
    data = scope_dict()
    data["allowed_targets"] = [{"host": host, "schemes": ["https"], "ports": [port], "allowed_paths": paths}]
    data["allowed_operations"] = ["dns_metadata", "tls_metadata"] + (["http_metadata"] if paths else [])
    data["max_requests"] = budget
    loaded = parse_scope(dump(data), now=NOW)
    assert len(loaded.planned) == 2 + len(paths)
    assert all(op.host == host.lower() and op.port == port for op in loaded.planned)
    assert json.loads(loaded.canonical_json)["max_requests"] == budget


@given(st.binary(max_size=200).map(lambda b: b.decode("latin-1")))
def test_arbitrary_text_never_crashes_the_scope_parser_it_only_refuses(text: str) -> None:
    try:
        parse_scope(text, now=NOW)
    except ScopedAgentError:
        return
    except (yaml.YAMLError, RecursionError) as exc:  # pragma: no cover - would be a bug: errors must be ScopeError
        raise AssertionError(f"raw {type(exc).__name__} escaped the parser") from exc


ACTORS = [Actor(ActorType.HUMAN, "alice"), Actor(ActorType.WORKER, "w"), Actor(ActorType.MODEL, "m")]


@given(st.lists(st.tuples(st.sampled_from(list(RunState)), st.sampled_from(ACTORS)), max_size=30))
def test_no_sequence_of_attempts_can_leave_a_terminal_run_state_or_let_the_model_move_anything(
    steps: list[tuple[RunState, Actor]],
) -> None:
    state = RunState.CREATED
    for destination, actor in steps:
        try:
            check_run_transition(state, destination, actor)
        except StateError:
            continue
        assert actor.type is not ActorType.MODEL
        assert state not in (RunState.EXPORTED, RunState.CANCELED, RunState.RETRIED)
        state = destination


@given(
    st.lists(
        st.tuples(
            st.sampled_from(list(FindingStatus)),
            st.sampled_from(ACTORS),
            st.text(max_size=5),
            st.integers(min_value=-1, max_value=3),
        ),
        max_size=30,
    )
)
def test_a_finding_reaches_validated_only_through_a_human_with_a_reason_and_evidence(
    steps: list[tuple[FindingStatus, Actor, str, int]],
) -> None:
    status = FindingStatus.DRAFT
    for destination, actor, reason, evidence in steps:
        try:
            check_finding_transition(status, destination, actor=actor, reason=reason, evidence_count=evidence)
        except StateError:
            continue
        if destination is not FindingStatus.NEEDS_VALIDATION:
            assert actor.type is ActorType.HUMAN and reason.strip() and evidence >= 1
        status = destination
        assert status is not FindingStatus.DRAFT


@pytest.fixture(scope="module")
def shared_db(tmp_path_factory: pytest.TempPathFactory) -> Any:
    from tests.support import make_database  # noqa: PLC0415

    database = make_database(tmp_path_factory.mktemp("property-db"))
    yield database
    database.close()


@settings(max_examples=60, deadline=None)
@given(st.lists(st.tuples(st.sampled_from(["reserve", "release"]), st.integers(min_value=1, max_value=7)), max_size=30))
def test_budget_accounting_never_exceeds_the_total_or_goes_negative(
    shared_db: Any, operations: list[tuple[str, int]]
) -> None:
    from scopedagent.domain.models import Run  # noqa: PLC0415
    from scopedagent.errors import BudgetError  # noqa: PLC0415
    from scopedagent.policy.budget import release, reserve  # noqa: PLC0415
    from tests.support import run_in_state  # noqa: PLC0415

    run_id = run_in_state(shared_db, "COLLECTING")  # a fresh run per example, total_budget 12
    held: list[Any] = []
    for action, units in operations:
        if action == "reserve":
            try:
                with shared_db.begin() as session:
                    held.append(reserve(session, run_id, units=units))
            except BudgetError:
                assert sum(p.units for p in held) + units > 12  # refused only when it really would not fit
        elif held:
            with shared_db.begin() as session:
                release(session, held.pop())
        with shared_db.begin() as session:
            run = session.get(Run, run_id)
            assert run is not None and 0 <= run.budget_spent <= 12
            assert run.budget_spent == sum(p.units for p in held)
