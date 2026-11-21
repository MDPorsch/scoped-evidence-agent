"""M4: rewording a run's drafts. The model gets rule sentences only, hosts masked; what it returns is checked item by item; every failure leaves the rule's text."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from scopedagent import __version__
from scopedagent.ai.config import AiConfig, AiLimits, default_config
from scopedagent.ai.protocol import ModelUnavailable, RewordReply, RewordRequest
from scopedagent.ai.reword import FIELDS, pieces_of, reword_run
from scopedagent.domain.state_machine import Actor, ActorType
from scopedagent.errors import ErrorCode, StateError
from scopedagent.output.report import build_report, render_json, render_markdown
from scopedagent.storage.audit import verify_chain
from scopedagent.storage.wordings import list_wordings, store_wording
from tests.support import NOW, findings_of, make_env, run_pack

pytestmark = pytest.mark.milestone("M4")

HOSTS = ["bad.example.invalid"]
KEY = "sk-ant-api03-SYNTHETIC-KEY-0001"
FACTS = [
    "Apache/2.4.49",
    "PHP/5.6.40",
    "Disallow: /admin",
    "cdn.other.example.invalid",
    "SYNTHETIC-COOKIE",
    "SYNTHETIC-KEY-0001",
]


class Scripted:
    provider, model = "test", "scripted-1"

    def __init__(self, respond: Callable[[RewordRequest], RewordReply] | None = None) -> None:
        self.requests: list[RewordRequest] = []
        self.respond = respond or (lambda r: RewordReply({i.id: "Put simply: " + i.text for i in r.items}, 100, 50))

    def reword(self, request: RewordRequest) -> RewordReply:
        self.requests.append(request)
        return self.respond(request)


@pytest.fixture
def env(tmp_path: Path) -> Any:
    db, store, data_dir = make_env(tmp_path)
    yield db, store, data_dir
    db.close()


@pytest.fixture
def run_id(env: Any) -> str:
    return str(run_pack(env, "misconfigured").run_id)


def go(
    env: Any, run: str, adapter: Any, *, config: AiConfig | None = None, hosts: list[str] | None = None, **kw: Any
) -> Any:
    db, _, _ = env
    return reword_run(
        db,
        run,
        adapter=adapter,
        config=config or default_config("offline"),
        hosts=HOSTS if hosts is None else hosts,
        now=NOW,
        **kw,
    )


def rows(env: Any, sql: str, **params: Any) -> list[Any]:
    db, _, _ = env
    with db.begin() as session:
        return list(session.execute(text(sql), params).all())


def piece_count(env: Any, run: str) -> int:
    return sum(len(pieces_of(details)) for _, details in findings_of(env[0], run))


# -------------------------------------------------------------------------------------------------- the pieces ----
def test_the_pieces_are_the_rule_sentences_and_nothing_the_target_said(env: Any, run_id: str) -> None:
    (finding, details), *_ = findings_of(env[0], run_id)
    pieces = pieces_of(details)
    fields = {p.field for p in pieces}
    assert fields == set(FIELDS)
    assert FIELDS == {
        "condition": 300,
        "precondition": 300,
        "unknown": 300,
        "attacker_position": 200,
        "basis": 300,
        "remediation": 500,
        "severity_basis": 200,
    }
    assert [p.text for p in pieces if p.field == "condition"] == details.conditions
    assert [p.index for p in pieces if p.field == "unknown"] == [0, 1]
    assert all(p.limit == FIELDS[p.field] and 0 < len(p.text) <= p.limit for p in pieces)
    blob = " ".join(p.text for p in pieces)
    for fact in details.facts:
        assert fact not in blob
    assert finding.title and not any(f in blob for f in FACTS)


def test_every_finding_of_the_shipped_packs_has_pieces_within_their_limits(env: Any) -> None:
    for name in ("misconfigured", "poisoned", "ai-support-bot"):
        result = run_pack(env, name)
        for _, details in findings_of(env[0], result.run_id):
            pieces = pieces_of(details)
            assert pieces and all(len(p.text) <= p.limit for p in pieces)


# ----------------------------------------------------------------------------------------------- the happy path ----
def test_rewording_a_run_stores_a_second_wording_beside_the_rule_text(env: Any, run_id: str) -> None:
    summary = go(env, run_id, Scripted())
    total = piece_count(env, run_id)
    assert (summary.findings, summary.calls, summary.reworded, summary.kept) == (8, 8, total, 0)
    assert summary.statuses == {"ok": 8} and summary.tokens == 8 * 150
    db, _, _ = env
    with db.begin() as session:
        for finding, details in findings_of(db, run_id):
            stored = list_wordings(session, finding.id)
            originals = {(p.field, p.index): p.text for p in pieces_of(details)}
            assert {(w.field, w.item_index) for w in stored} == set(originals)
            for w in stored:
                assert w.text == "Put simply: " + originals[(w.field, w.item_index)]
                assert (w.model, w.prompt_version) == ("scripted-1", "reword-v1") and len(w.original_sha256) == 64


def test_the_rule_text_and_the_finding_are_untouched(env: Any, run_id: str) -> None:
    db, _, _ = env
    before = [(f.status, f.revision, f.reviewer_id, d.model_dump_json()) for f, d in findings_of(db, run_id)]
    go(env, run_id, Scripted())
    after = [(f.status, f.revision, f.reviewer_id, d.model_dump_json()) for f, d in findings_of(db, run_id)]
    assert before == after
    with db.begin() as session:
        assert session.execute(text("SELECT state FROM runs WHERE id = :r"), {"r": run_id}).scalar() == "DRAFTED"
        assert verify_chain(session, run_id) > 0


def test_a_second_run_of_the_command_asks_for_nothing_new(env: Any, run_id: str) -> None:
    go(env, run_id, Scripted())
    again = Scripted()
    summary = go(env, run_id, again)
    assert again.requests == [] and (summary.calls, summary.reworded) == (0, 0)
    assert rows(env, "SELECT count(*) FROM model_calls")[0][0] == 8


def test_a_partly_worded_finding_is_asked_only_for_what_is_missing(env: Any, run_id: str) -> None:
    db, _, _ = env
    (finding, details), *_ = findings_of(db, run_id)
    with db.begin() as session:
        first = pieces_of(details)[0]
        store_wording(
            session,
            finding_id=finding.id,
            run_id=run_id,
            field=first.field,
            index=first.index,
            original=first.text,
            wording="Put simply: " + first.text,
            model="m",
            prompt_version="reword-v1",
            actor=Actor(ActorType.WORKER, "w"),
            now=NOW,
        )
    model = Scripted()
    go(env, run_id, model, finding_id=finding.id)
    sent = {i.id for r in model.requests for i in r.items}
    assert f"{first.field}-{first.index}" not in sent and len(sent) == len(pieces_of(details)) - 1


def test_one_finding_can_be_chosen(env: Any, run_id: str) -> None:
    (finding, _), *_ = findings_of(env[0], run_id)
    model = Scripted()
    summary = go(env, run_id, model, finding_id=finding.id)
    assert (summary.findings, summary.calls, len(model.requests)) == (1, 1, 1)


# --------------------------------------------------------------------------------------------- what is sent ----
def test_no_host_name_and_no_target_text_is_ever_sent(env: Any, run_id: str) -> None:
    model = Scripted()
    go(env, run_id, model)
    sent = " ".join(i.text for r in model.requests for i in r.items)
    assert "bad.example.invalid" not in sent and "example.invalid" not in sent
    for fact in FACTS:
        assert fact not in sent
    assert "HOST_A" in sent
    assert {r.prompt_version for r in model.requests} == {"reword-v1"} and all(
        len(r.items) <= 40 for r in model.requests
    )


def test_a_host_is_sent_when_masking_is_off(env: Any, run_id: str) -> None:
    model = Scripted()
    config = default_config("offline").model_copy(update={"mask_hosts": False})
    go(env, run_id, model, config=config)
    sent = " ".join(i.text for r in model.requests for i in r.items)
    assert "bad.example.invalid" in sent and "HOST_A" not in sent


def test_a_wording_that_is_too_long_once_its_hosts_are_put_back_is_dropped(env: Any, run_id: str) -> None:
    sentence = "The certificate's names do not cover HOST_A."

    def respond(request: RewordRequest) -> RewordReply:
        texts = {i.id: "Put simply: " + i.text for i in request.items}
        for item in request.items:
            if (
                item.text == sentence
            ):  # 15 placeholders of 6 characters become 15 hosts of 19: past the 300-character limit
                texts[item.id] = sentence + " HOST_A" * 14
        return RewordReply(texts, 5, 5)

    summary = go(env, run_id, Scripted(respond))
    assert summary.kept == 1 and summary.reworded == piece_count(env, run_id) - 1
    assert rows(env, "SELECT count(*) FROM finding_wordings WHERE length(text) > 300")[0][0] == 0
    assert rows(env, "SELECT detail FROM model_calls WHERE items_rejected > 0")[0][0] == "length 1"


def test_a_draft_made_before_there_were_details_is_left_alone(tmp_path: Path) -> None:
    from alembic import command  # noqa: PLC0415

    from scopedagent.storage.database import DataDir, _alembic_config, open_database, upgrade_database  # noqa: PLC0415
    from tests.support import raw_connection  # noqa: PLC0415

    data_dir = DataDir(tmp_path / "old")
    data_dir.root.mkdir(mode=0o700)
    data_dir.db_path.touch(mode=0o600)
    command.upgrade(_alembic_config(data_dir.db_path), "0001")
    with raw_connection(data_dir.db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            "INSERT INTO engagements VALUES ('e1','lab','local-lab-consent','"
            + "a" * 64
            + "','{}','2026-12-31T00:00:00.000000Z','2026-11-20T00:00:00.000000Z','active');"
            "INSERT INTO runs (id, engagement_id, created_by, mode, state, total_budget, budget_spent, attempt, created_at) "
            "VALUES ('r1','e1','alice','offline','DRAFTED',12,5,1,'2026-11-20T00:00:00.000000Z');"
            "INSERT INTO finding_drafts VALUES ('f1','r1','An old title','tls-misconfiguration',0.5,'DRAFT',NULL,1,'2026-11-20T00:00:00.000000Z');"
        )
    upgrade_database(data_dir)
    db = open_database(data_dir)
    try:
        model = Scripted()
        summary = reword_run(db, "r1", adapter=model, config=default_config("offline"), hosts=HOSTS, now=NOW)
    finally:
        db.close()
    assert (summary.findings, summary.calls) == (0, 0) and model.requests == []


def test_the_host_is_put_back_in_the_stored_wording(env: Any, run_id: str) -> None:
    go(env, run_id, Scripted())
    stored = rows(env, "SELECT text FROM finding_wordings WHERE text LIKE '%do not cover%'")
    assert stored and all("bad.example.invalid" in r[0] and "HOST_" not in r[0] for r in stored)


def test_a_title_a_fact_a_step_and_a_guide_are_never_pieces(env: Any, run_id: str) -> None:
    model = Scripted()
    go(env, run_id, model)
    sent = " ".join(i.text for r in model.requests for i in r.items)
    for finding, details in findings_of(env[0], run_id):
        assert finding.title not in sent
        for step in details.validation_steps:
            assert step.action not in sent and (step.example_invocation or "x-none") not in sent
        for entry in details.decision_guide:
            assert entry.outcome not in sent


# ------------------------------------------------------------------------------------------ what comes back ----
def test_an_item_that_changes_a_number_is_dropped_and_the_others_are_kept(env: Any, run_id: str) -> None:
    def respond(request: RewordRequest) -> RewordReply:
        texts = {i.id: "Put simply: " + i.text for i in request.items}
        if "condition-3" in texts:
            texts["condition-3"] = texts["condition-3"].replace("1024", "512")
        return RewordReply(texts, 10, 10)

    model = Scripted(respond)
    summary = go(env, run_id, model)
    total = piece_count(env, run_id)
    assert (summary.reworded, summary.kept) == (total - 1, 1)
    detail = rows(
        env,
        "SELECT items_sent, items_accepted, items_rejected, status, detail FROM model_calls WHERE items_rejected > 0",
    )
    assert (
        len(detail) == 1
        and detail[0][2] == 1
        and detail[0][0] == detail[0][1] + 1
        and detail[0][3] == "ok"
        and detail[0][4] == "tokens 1"
    )
    assert rows(env, "SELECT count(*) FROM finding_wordings WHERE text LIKE '%512%'")[0][0] == 0


@pytest.mark.parametrize(
    ("make", "status"),
    [
        (lambda: ModelUnavailable("unavailable", "RateLimitError"), "unavailable"),
        (lambda: ModelUnavailable("refused", "refusal"), "refused"),
        (lambda: ModelUnavailable("invalid", "the reply was not the requested JSON"), "invalid"),
    ],
)
def test_a_failed_call_is_recorded_and_the_next_finding_is_still_tried(
    env: Any, run_id: str, make: Callable[[], ModelUnavailable], status: str
) -> None:
    def respond(_request: RewordRequest) -> RewordReply:
        raise make()

    summary = go(env, run_id, Scripted(respond))
    assert summary.statuses == {status: 8} and summary.reworded == 0 and summary.kept == piece_count(env, run_id)
    stored = rows(env, "SELECT status, items_accepted, input_tokens, output_tokens, detail FROM model_calls")
    assert (
        len(stored) == 8
        and {r[0] for r in stored} == {status}
        and {r[1] for r in stored} == {0}
        and {r[2] for r in stored} == {0}
    )
    assert rows(env, "SELECT count(*) FROM finding_wordings")[0][0] == 0


def test_a_bug_in_an_adapter_is_unavailable_and_its_message_is_never_stored(env: Any, run_id: str) -> None:
    def respond(_request: RewordRequest) -> RewordReply:
        raise RuntimeError(f"secret detail {KEY} and a sentence")

    summary = go(env, run_id, Scripted(respond), secrets=(KEY,))
    assert summary.statuses == {"unavailable": 8}
    details = {r[0] for r in rows(env, "SELECT detail FROM model_calls")}
    assert details == {"RuntimeError"}
    blob = " ".join(r[0] for r in rows(env, "SELECT reason FROM audit_events"))
    assert KEY not in blob and "secret detail" not in blob


def test_a_stored_detail_is_one_short_plain_line(env: Any, run_id: str) -> None:
    def respond(_request: RewordRequest) -> RewordReply:
        raise ModelUnavailable("unavailable", "line one\nline two " + "x" * 500)

    go(env, run_id, Scripted(respond))
    for (detail,) in rows(env, "SELECT detail FROM model_calls"):
        assert "\n" not in detail and len(detail) <= 200


def test_an_echoed_key_is_refused_item_by_item(env: Any, run_id: str) -> None:
    def respond(request: RewordRequest) -> RewordReply:
        texts = {i.id: "Put simply: " + i.text for i in request.items}
        first = request.items[0].id
        texts[first] = texts[first] + " x" + KEY
        return RewordReply(texts, 1, 1)

    summary = go(env, run_id, Scripted(respond), secrets=(KEY,))
    assert summary.reworded == piece_count(env, run_id) - 8 and summary.kept == 8
    assert rows(env, "SELECT count(*) FROM finding_wordings WHERE text LIKE '%SYNTHETIC%'")[0][0] == 0
    assert rows(env, "SELECT DISTINCT detail FROM model_calls")[0][0] == "secret 1"


def test_a_model_that_returns_the_wrong_ids_changes_nothing(env: Any, run_id: str) -> None:
    summary = go(env, run_id, Scripted(lambda r: RewordReply({"nope": "x"}, 1, 1)))
    assert summary.statuses == {"invalid": 8} and rows(env, "SELECT count(*) FROM finding_wordings")[0][0] == 0


def test_a_reply_with_extra_ids_or_missing_ids_is_invalid_as_a_whole(env: Any, run_id: str) -> None:
    def respond(request: RewordRequest) -> RewordReply:
        texts = {i.id: i.text for i in request.items[:-1]}
        return RewordReply(texts, 1, 1)

    assert go(env, run_id, Scripted(respond)).statuses == {"invalid": 8}


# ------------------------------------------------------------------------------------------------- the budget ----
def test_calls_beyond_the_run_limit_are_refused_and_recorded(env: Any, run_id: str) -> None:
    config = default_config("offline").model_copy(update={"limits": AiLimits(max_calls_per_run=3)})
    model = Scripted()
    summary = go(env, run_id, model, config=config)
    assert summary.statuses == {"ok": 3, "budget_exhausted": 5} and len(model.requests) == 3
    skipped = rows(env, "SELECT items_sent, input_tokens, detail FROM model_calls WHERE status = 'budget_exhausted'")
    assert len(skipped) == 5 and {r[0] for r in skipped} == {0} and {r[1] for r in skipped} == {0}
    denied = rows(env, "SELECT decision FROM audit_events WHERE action = 'model.reword' AND decision = 'denied'")
    assert len(denied) == 5


def test_the_limit_counts_calls_made_by_earlier_commands(env: Any, run_id: str) -> None:
    config = default_config("offline").model_copy(update={"limits": AiLimits(max_calls_per_run=3)})
    go(env, run_id, Scripted(), config=config)
    model = Scripted()
    summary = go(env, run_id, model, config=config)
    assert model.requests == [] and summary.calls == 0 and summary.statuses == {"budget_exhausted": 5}


def test_a_call_that_could_spend_more_tokens_than_the_run_has_left_is_refused(env: Any, run_id: str) -> None:
    config = default_config("offline").model_copy(
        update={"limits": AiLimits(max_output_tokens=256, max_total_tokens=1000)}
    )
    model = Scripted(lambda r: RewordReply({i.id: "Put simply: " + i.text for i in r.items}, 500, 400))
    summary = go(env, run_id, model, config=config)
    assert summary.statuses["ok"] == 1 and summary.statuses["budget_exhausted"] == 7 and len(model.requests) == 1
    assert rows(env, "SELECT sum(input_tokens + output_tokens) FROM model_calls")[0][0] == 900


def test_the_estimate_counts_the_prompt_and_the_reply_cap() -> None:
    from scopedagent.ai.protocol import RewordItem  # noqa: PLC0415
    from scopedagent.ai.reword import estimate_tokens  # noqa: PLC0415

    request = RewordRequest((RewordItem("a", "x" * 300, 300), RewordItem("b", "y" * 301, 300)), "reword-v1")
    assert estimate_tokens(request, 2048) == 2048 + -(-601 // 3)


# ---------------------------------------------------------------------------------- who may write, and how ----
def test_the_model_cannot_store_a_wording(env: Any, run_id: str) -> None:
    db, _, _ = env
    (finding, _), *_ = findings_of(db, run_id)
    with pytest.raises(StateError) as caught, db.begin() as session:
        store_wording(
            session,
            finding_id=finding.id,
            run_id=run_id,
            field="basis",
            index=0,
            original="x",
            wording="y",
            model="m",
            prompt_version="v",
            actor=Actor(ActorType.MODEL, "assistant"),
            now=NOW,
        )
    assert caught.value.code is ErrorCode.STATE_003
    denied = rows(env, "SELECT actor_type FROM audit_events WHERE action = 'wording.store' AND decision = 'denied'")
    assert denied == [("model",)]


def test_a_wording_for_a_field_outside_the_list_or_a_negative_index_is_refused(env: Any, run_id: str) -> None:
    db, _, _ = env
    (finding, _), *_ = findings_of(db, run_id)
    for field, index in (("title", 0), ("facts", 0), ("condition", -1)):
        with pytest.raises((StateError, DBAPIError, ValueError)), db.begin() as session:
            store_wording(
                session,
                finding_id=finding.id,
                run_id=run_id,
                field=field,
                index=index,
                original="x",
                wording="y",
                model="m",
                prompt_version="v",
                actor=Actor(ActorType.WORKER, "w"),
                now=NOW,
            )


def test_wordings_and_calls_cannot_be_changed_or_deleted(env: Any, run_id: str) -> None:
    go(env, run_id, Scripted())
    db, _, _ = env
    for statement, match in (
        ("UPDATE finding_wordings SET text = 'x'", "append-only"),
        ("DELETE FROM finding_wordings", "append-only"),
        ("UPDATE model_calls SET status = 'ok'", "append-only"),
        ("DELETE FROM model_calls", "append-only"),
    ):
        with pytest.raises(DBAPIError, match=match), db.begin() as session:
            session.execute(text(statement))


def test_an_item_can_be_worded_only_once(env: Any, run_id: str) -> None:
    db, _, _ = env
    (finding, details), *_ = findings_of(db, run_id)
    first = pieces_of(details)[0]

    def store() -> None:
        with db.begin() as session:
            store_wording(
                session,
                finding_id=finding.id,
                run_id=run_id,
                field=first.field,
                index=first.index,
                original=first.text,
                wording="Put simply: " + first.text,
                model="m",
                prompt_version="reword-v1",
                actor=Actor(ActorType.WORKER, "w"),
                now=NOW,
            )

    store()
    with pytest.raises(DBAPIError):
        store()


# ------------------------------------------------------------------------------------------------- the audit ----
def test_each_call_is_audited_with_the_model_the_prompt_and_the_input_hash_but_never_a_sentence(
    env: Any, run_id: str
) -> None:
    go(env, run_id, Scripted())
    events = rows(
        env, "SELECT actor_type, actor_id, decision, reason FROM audit_events WHERE action = 'model.reword' ORDER BY id"
    )
    assert len(events) == 8
    for actor_type, actor_id, decision, reason in events:
        assert (actor_type, actor_id, decision) == ("worker", "reworder", "allowed")
        assert re.search(
            r"model scripted-1 prompt reword-v1 input [0-9a-f]{12} sent \d+ accepted \d+ tokens 100\+50", reason
        ), reason
        assert "certificate" not in reason and "bad.example" not in reason
    hashes = {r[0] for r in rows(env, "SELECT input_sha256 FROM model_calls")}
    assert len(hashes) == 8 and all(re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes)


def test_the_input_hash_is_of_what_was_sent_so_the_same_input_gives_the_same_hash(env: Any) -> None:
    first = run_pack(env, "misconfigured").run_id
    go(env, first, Scripted())
    second = run_pack(env, "misconfigured").run_id
    go(env, second, Scripted())
    a = rows(env, "SELECT input_sha256 FROM model_calls WHERE run_id = :r ORDER BY id", r=first)
    b = rows(env, "SELECT input_sha256 FROM model_calls WHERE run_id = :r ORDER BY id", r=second)
    assert a == b and len(a) == 8


# ------------------------------------------------------------------------------------------------ the reports ----
def test_a_report_without_wordings_has_no_wording_key_or_note_at_all(env: Any, run_id: str) -> None:
    db, _, _ = env
    with db.begin() as session:
        report = build_report(session, run_id, tool_version=__version__)
    assert all("wordings" not in f for f in report["findings"])
    assert not any("a model reworded" in n for n in report["notes"])


def test_a_report_with_wordings_labels_them_as_model_written_and_keeps_the_rule_text(env: Any, run_id: str) -> None:
    go(env, run_id, Scripted())
    db, _, _ = env
    with db.begin() as session:
        report = build_report(session, run_id, tool_version=__version__)
    first = report["findings"][0]
    assert first["details"]["conditions"][0].startswith("The service negotiated")
    wording = first["wordings"][0]
    assert set(wording) == {"field", "index", "text", "model", "prompt_version"} and wording["model"] == "scripted-1"
    assert wording["text"].startswith("Put simply: ")
    md = render_markdown(report)
    assert (
        "Wording by a model (not verified; the rule's text above is authoritative)" in md
        and "Put simply: The service negotiated" in md
    )
    assert render_json(report).isascii()
    assert any("a model reworded" in n for n in report["notes"])


def test_the_same_report_with_the_same_wordings_is_byte_identical(env: Any, run_id: str) -> None:
    go(env, run_id, Scripted())
    db, _, _ = env
    with db.begin() as session:
        a = render_json(build_report(session, run_id, tool_version=__version__))
        b = render_json(build_report(session, run_id, tool_version=__version__))
    assert a == b
