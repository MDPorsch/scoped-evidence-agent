"""M3: the finding repository's own rules: what a draft may carry, how a reference resolves, what a missing detail does."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from scopedagent.domain.findings import FindingDetails
from scopedagent.domain.schemas import FindingDraftCreate
from scopedagent.errors import ErrorCode, PolicyError, StateError
from scopedagent.pipeline.correlate import WORKER, details_for, load_views
from scopedagent.pipeline.rules import RuleContext, run_rules
from scopedagent.policy.scope import parse_scope
from scopedagent.storage.repositories import (
    create_finding_draft,
    get_finding_details,
    list_findings,
    resolve_finding,
)
from tests.support import NOW, make_env, observation_ids, run_pack, scope_text, sql_insert, stamp

pytestmark = pytest.mark.milestone("M3")


@pytest.fixture
def env(tmp_path: Path) -> Any:
    db, store, data_dir = make_env(tmp_path)
    yield db, store, data_dir
    db.close()


def one_draft(env: Any) -> tuple[Any, str, Any, list[str]]:
    """A run collected from the misconfigured pack, its first rule draft and that draft's details, not yet stored."""
    db, _, _ = env
    result = run_pack(env, "misconfigured")
    config = parse_scope(scope_text("misconfigured"), now=NOW).config
    with db.begin() as session:
        draft = run_rules(RuleContext(load_views(session, result.run_id), config))[0]
    return db, result.run_id, details_for(draft, config), observation_ids(db, result.run_id)


def correlating(db: Any, run_id: str) -> None:
    """Take a collected run back to CORRELATING so that a draft can be created by hand."""
    with db.begin() as session:
        session.execute(text("UPDATE runs SET state = 'CORRELATING' WHERE id = :r"), {"r": run_id})


def test_a_draft_with_details_must_be_filed_under_its_own_class(env: Any) -> None:
    db, run_id, details, ids = one_draft(env)
    correlating(db, run_id)
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        create_finding_draft(
            session,
            run_id=run_id,
            draft=FindingDraftCreate(title="A title", category="permissive_cors", confidence=0.5),
            observation_ids=ids[:1],
            actor=WORKER,
            now=NOW,
            details=details,
        )
    assert caught.value.code is ErrorCode.POLICY_003 and "vulnerability class" in str(caught.value)


def test_a_step_may_cite_only_what_the_draft_cites(env: Any) -> None:
    db, run_id, details, ids = one_draft(env)
    correlating(db, run_id)
    stray = ids[0] if ids[0] not in {c for s in details.validation_steps for c in s.cites} else ids[2]
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        create_finding_draft(
            session,
            run_id=run_id,
            draft=FindingDraftCreate(title="A title", category=details.vulnerability_class.value, confidence=0.5),
            observation_ids=[stray],
            actor=WORKER,
            now=NOW,
            details=details,
        )
    assert caught.value.code is ErrorCode.POLICY_002 and "cite only" in str(caught.value)
    with db.begin() as session:
        assert session.execute(text("SELECT count(*) FROM finding_drafts")).scalar() == 8  # only the run's own drafts


def test_a_finding_made_without_details_has_none_to_read(env: Any) -> None:
    db, run_id, _, ids = one_draft(env)
    correlating(db, run_id)
    with db.begin() as session:
        finding = create_finding_draft(
            session,
            run_id=run_id,
            draft=FindingDraftCreate(title="A plain draft", category="tls-misconfiguration", confidence=0.5),
            observation_ids=ids[:1],
            actor=WORKER,
            now=NOW,
        )
        finding_id = finding.id
    with pytest.raises(StateError) as caught, db.begin() as session:
        get_finding_details(session, finding_id)
    assert caught.value.code is ErrorCode.STATE_001


def test_details_are_validated_again_when_they_are_read_back(env: Any) -> None:
    db, run_id, details, _ids = one_draft(env)
    correlating(db, run_id)
    with db.begin() as session:
        finding = create_finding_draft(
            session,
            run_id=run_id,
            draft=FindingDraftCreate(title="A title", category=details.vulnerability_class.value, confidence=0.5),
            observation_ids=list(details.validation_steps[0].cites),
            actor=WORKER,
            now=NOW,
            details=details,
        )
        finding_id = finding.id
    with db.begin() as session:
        assert isinstance(get_finding_details(session, finding_id), FindingDetails)


# ---------------------------------------------------------------------------------------------- references ----
def seed_findings(db: Any, ids: list[str]) -> None:
    with db.begin() as session:
        sql_insert(
            session,
            "engagements",
            id="e9",
            label="x9",
            owner_approval_ref="local-lab-consent",
            scope_sha256="b" * 64,
            scope_json="{}",
            expires_at=stamp(),
            created_at=stamp(),
            status="active",
        )
        sql_insert(
            session,
            "runs",
            id="r9",
            engagement_id="e9",
            created_by="alice",
            mode="offline",
            state="DRAFTED",
            total_budget=1,
            budget_spent=0,
            attempt=1,
            created_at=stamp(),
        )
        for finding_id in ids:
            sql_insert(
                session,
                "finding_drafts",
                id=finding_id,
                run_id="r9",
                title="A title",
                category="permissive_cors",
                confidence=0.5,
                status="NEEDS_VALIDATION",
                reviewer_id=None,
                revision=1,
                created_at=stamp(),
            )


def test_a_reference_is_a_full_id_or_a_unique_prefix_of_at_least_eight_characters(env: Any) -> None:
    db, _, _ = env
    seed_findings(db, ["aaaaaaaa1111", "bbbbbbbb2222"])
    with db.begin() as session:
        assert resolve_finding(session, "aaaaaaaa1111").id == "aaaaaaaa1111"
        assert resolve_finding(session, "aaaaaaaa").id == "aaaaaaaa1111"
        assert resolve_finding(session, "bbbbbbbb22").id == "bbbbbbbb2222"


@pytest.mark.parametrize("ref", ["", "aaaaaaa", "a", "zzzzzzzz", "aaaaaaaa11112"])
def test_a_short_unknown_or_too_long_reference_is_refused(env: Any, ref: str) -> None:
    db, _, _ = env
    seed_findings(db, ["aaaaaaaa1111"])
    with pytest.raises(PolicyError), db.begin() as session:
        resolve_finding(session, ref)


def test_a_reference_that_matches_two_findings_is_refused_not_guessed(env: Any) -> None:
    db, _, _ = env
    seed_findings(db, ["aaaaaaaa1111", "aaaaaaaa2222"])
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        resolve_finding(session, "aaaaaaaa")
    assert caught.value.code is ErrorCode.POLICY_003 and "more than one" in str(caught.value)


@pytest.mark.parametrize("ref", ["aaaa%aaaa", "aaaa_aaaa", "a%%%%%%%%", "________", "%%%%%%%%"])
def test_wildcard_characters_in_a_reference_are_not_wildcards(env: Any, ref: str) -> None:
    db, _, _ = env
    seed_findings(db, ["aaaabaaaa1", "aaaaaaaaa2"])
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        resolve_finding(session, ref)
    assert caught.value.code is ErrorCode.POLICY_002


def test_a_backslash_in_a_reference_is_just_a_character(env: Any) -> None:
    db, _, _ = env
    seed_findings(db, ["aaaaaaaa1"])
    with pytest.raises(PolicyError), db.begin() as session:
        resolve_finding(session, "aaaaaaa\\")


def test_findings_are_listed_in_the_order_they_were_drafted(env: Any) -> None:
    db, _, _ = env
    seed_findings(db, ["zzzzzzzz1", "aaaaaaaa2", "mmmmmmmm3"])
    with db.begin() as session:
        assert [f.id for f in list_findings(session, "r9")] == ["zzzzzzzz1", "aaaaaaaa2", "mmmmmmmm3"]
        assert list_findings(session, "nope") == []


def test_the_state_machine_still_refuses_drafts_outside_correlation(env: Any) -> None:
    db, run_id, details, ids = one_draft(env)
    with pytest.raises(StateError) as caught, db.begin() as session:
        create_finding_draft(
            session,
            run_id=run_id,
            draft=FindingDraftCreate(title="A title", category=details.vulnerability_class.value, confidence=0.5),
            observation_ids=ids[:1],
            actor=WORKER,
            now=NOW,
            details=details,
        )
    assert caught.value.code is ErrorCode.STATE_001


def test_a_backslash_in_a_reference_matches_only_a_backslash(env: Any) -> None:
    db, _, _ = env
    seed_findings(db, ["aaaaaaa%"])
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        resolve_finding(session, "aaaaaaa\\")
    assert caught.value.code is ErrorCode.POLICY_002


def test_a_reference_matches_the_start_of_an_id_and_nothing_in_the_middle(env: Any) -> None:
    db, _, _ = env
    seed_findings(db, ["xxaaaaaaaa11"])
    with pytest.raises(PolicyError) as caught, db.begin() as session:
        resolve_finding(session, "aaaaaaaa")
    assert caught.value.code is ErrorCode.POLICY_002
    with db.begin() as session:
        assert resolve_finding(session, "xxaaaaaa").id == "xxaaaaaaaa11"
