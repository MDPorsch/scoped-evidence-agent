"""M6, D-E44: the controller accepts what the sandbox returned or refuses all of it. The directory is untrusted."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from scopedagent.adapters.offline import OfflineHttp, normalized_input
from scopedagent.adapters.pack import Pack
from scopedagent.errors import ErrorCode, LiveFailed
from scopedagent.live.collector import write_result
from scopedagent.live.leakguard import LeakGuard
from scopedagent.live.outputcheck import accept_results
from scopedagent.live.protocol import MAX_ARTIFACT_BYTES, MAX_RESULT_BYTES
from scopedagent.policy.scope import PlannedOperation
from tests.support import assemble

pytestmark = pytest.mark.milestone("M6")

HOST = "lab.example.invalid"
OP0 = PlannedOperation("http_metadata", HOST, "https", 443, "/robots.txt")
OP1 = PlannedOperation("http_metadata", HOST, "https", 443, "/")
PLANNED = {0: OP0, 1: OP1}
SECRET = assemble("tok_live-", "SYNTHETIC", "-0001")
NO_SECRETS = LeakGuard([])


def make_result(op: PlannedOperation, body: str = "User-agent: *\nDisallow: /admin\n") -> Any:
    entry = {"status": 200, "headers": {"content-type": ["text/plain"]}, "body": body}
    pack = Pack("t", {}, {}, {f"{op.scheme}://{op.host}:{op.port}{op.path}": entry}, {}, {})
    return asyncio.run(OfflineHttp(pack, 100_000).collect(op))


def write_two(directory: Path) -> None:
    write_result(directory, 0, make_result(OP0))
    write_result(directory, 1, make_result(OP1, "<html>ok</html>"))


def refused(directory: Path, planned: dict[int, PlannedOperation] = PLANNED, guard: LeakGuard = NO_SECRETS) -> str:
    with pytest.raises(LiveFailed) as caught:
        accept_results(directory, planned, guard)
    assert caught.value.code is ErrorCode.LIVE_004 and "sandbox's output was refused" in str(caught.value)
    return str(caught.value)


def edit_result(directory: Path, which: int, **changes: Any) -> None:
    path = directory / f"result-{which}.json"
    data = json.loads(path.read_text())
    data.update(changes)
    path.write_text(json.dumps(data))


# -------------------------------------------------------------------------------------------- accepted ----
def test_a_complete_output_is_accepted_with_its_envelopes_and_artifacts(tmp_path: Path) -> None:
    write_two(tmp_path)
    accepted = accept_results(tmp_path, PLANNED, NO_SECRETS).results
    assert sorted(accepted) == [0, 1]
    first = accepted[0]
    assert first.envelope.observation_type == "http_metadata" and first.envelope.normalized_input == normalized_input(
        OP0
    )
    assert (
        first.body == b"User-agent: *\nDisallow: /admin\n"
        and first.body_mime == "text/plain"
        and first.body_status == "redacted"
    )
    assert (
        first.source_bytes == hashlib.sha256(make_result(OP0).source_bytes).hexdigest().encode()
    )  # the sandbox's own claim, as a line


def test_fewer_results_than_planned_is_fine_the_missing_ones_are_the_controllers_to_record(tmp_path: Path) -> None:
    write_result(tmp_path, 1, make_result(OP1))
    assert sorted(accept_results(tmp_path, PLANNED, NO_SECRETS).results) == [1]
    empty = tmp_path / "empty"
    empty.mkdir()
    assert accept_results(empty, PLANNED, NO_SECRETS).results == {}


def test_the_controller_redacts_an_artifact_again_whatever_the_sandbox_did(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0, "ok"))
    leaky = "token: SYNTHETIC-SECRET-VALUE-0001 and Bearer abcdefghijklmnop0123"
    data = leaky.encode()
    (tmp_path / "artifact-0.bin").write_bytes(data)
    edit_result(
        tmp_path,
        0,
        artifact={
            "file": "artifact-0.bin",
            "mime": "text/plain",
            "status": "redacted",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        },
    )
    body = accept_results(tmp_path, PLANNED, NO_SECRETS).results[0].body
    assert (
        body is not None
        and b"SYNTHETIC-SECRET-VALUE-0001" not in body
        and b"abcdefghijklmnop0123" not in body
        and b"[REDACTED]" in body
    )


def test_a_placeholder_artifact_is_kept_as_it_is(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0, "ok"))
    data = b"[binary content: 3 bytes, not stored]"
    (tmp_path / "artifact-0.bin").write_bytes(data)
    edit_result(
        tmp_path,
        0,
        artifact={
            "file": "artifact-0.bin",
            "mime": "text/plain",
            "status": "metadata_only",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        },
    )
    accepted = accept_results(tmp_path, PLANNED, NO_SECRETS).results[0]
    assert accepted.body == data and accepted.body_status == "metadata_only"


# --------------------------------------------------------------------------------------------- refused ----
@pytest.mark.parametrize(
    "name",
    [
        "notes.txt",
        "result-0.json.bak",
        "result-x.json",
        "artifact-0.bin.sh",
        ".hidden",
        "result-00000.json",
        "RESULT-0.json",
        "proof.json",
    ],
)
def test_any_file_that_is_not_a_result_or_an_artifact_refuses_the_whole_directory(tmp_path: Path, name: str) -> None:
    write_result(tmp_path, 1, make_result(OP1))
    try:
        (tmp_path / name).write_text("x")
    except (FileNotFoundError, OSError):
        pytest.skip("this name cannot be created on this file system")
    assert "not a result or an artifact" in refused(tmp_path)


def test_a_sub_directory_is_refused(tmp_path: Path) -> None:
    write_two(tmp_path)
    (tmp_path / "result-5.json").mkdir()
    PLANNED5 = {**PLANNED, 5: OP0}
    assert "not a plain file" in refused(tmp_path, PLANNED5)


def test_a_symbolic_link_is_refused_and_never_followed(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    outside = tmp_path.parent / "outside.json"
    outside.write_text((tmp_path / "result-0.json").read_text())
    (tmp_path / "result-0.json").unlink()
    (tmp_path / "result-0.json").symlink_to(outside)
    assert "not a plain file" in refused(tmp_path)


def test_a_hard_link_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    os.link(tmp_path / "result-0.json", tmp_path / "result-1.json")
    assert "not a plain file" in refused(tmp_path)


def test_a_result_over_its_size_limit_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    (tmp_path / "result-0.json").write_bytes(b" " * (MAX_RESULT_BYTES + 1))
    assert "over its size limit" in refused(tmp_path)


def test_an_artifact_over_its_size_limit_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    (tmp_path / "artifact-0.bin").write_bytes(b"x" * (MAX_ARTIFACT_BYTES + 1))
    assert "over its size limit" in refused(tmp_path)


def test_more_files_than_twice_the_operations_is_refused(tmp_path: Path) -> None:
    write_two(tmp_path)
    for i in range(2, 6):
        (tmp_path / f"result-{i}.json").write_text("{}")
    assert "more files than operations" in refused(tmp_path)


def test_a_result_for_an_operation_that_was_not_asked_for_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 9, make_result(OP0))
    (tmp_path / "artifact-9.bin").unlink()  # leave only the result, so it is the result that is refused
    assert "not asked for" in refused(tmp_path)
    (tmp_path / "result-9.json").unlink()
    (tmp_path / "artifact-9.bin").write_bytes(b"x")
    assert "not asked for" in refused(tmp_path)


def test_a_result_with_no_artifact_at_all_is_accepted(tmp_path: Path) -> None:
    result = make_result(OP0)
    object.__setattr__(result, "body", None)
    write_result(tmp_path, 0, result)
    accepted = accept_results(tmp_path, PLANNED, NO_SECRETS).results[0]
    assert accepted.body is None and not (tmp_path / "artifact-0.bin").exists()


@pytest.mark.parametrize("content", ["", "not json", "[]", "{}", '{"index": 0}', "null"])
def test_a_result_that_is_not_valid_is_refused(tmp_path: Path, content: str) -> None:
    (tmp_path / "result-0.json").write_text(content)
    assert "not a valid result" in refused(tmp_path)


def test_a_result_with_an_unknown_field_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    edit_result(tmp_path, 0, surprise=1)
    assert "not a valid result" in refused(tmp_path)


def test_a_result_that_names_another_index_than_its_file_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    edit_result(tmp_path, 0, index=1)
    assert "names a different operation" in refused(tmp_path)


def test_an_envelope_that_is_not_valid_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    path = tmp_path / "result-0.json"
    data = json.loads(path.read_text())
    data["envelope"]["payload"]["http_status"] = 999
    path.write_text(json.dumps(data))
    assert "envelope is not valid" in refused(tmp_path)


@pytest.mark.parametrize("change", ["type", "host", "port", "scheme", "input"])
def test_an_envelope_for_a_different_request_than_the_one_planned_is_refused(tmp_path: Path, change: str) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    path = tmp_path / "result-0.json"
    data = json.loads(path.read_text())
    envelope = data["envelope"]
    if change == "type":
        envelope.update(observation_type="ai_metadata", adapter="offline_ai")
        envelope["payload"] = {**envelope["payload"], "model_ids": []}
    elif change == "host":
        envelope["target"]["host"] = "other.example.invalid"
        envelope["payload"]["host"] = "other.example.invalid"
    elif change == "port":
        envelope["target"]["port"] = 8443
        envelope["payload"]["port"] = 8443
    elif change == "scheme":
        envelope["target"]["scheme"] = "http"
        envelope["payload"]["scheme"] = "http"
    else:
        envelope["normalized_input"] = "GET https://lab.example.invalid:443/other"
    path.write_text(json.dumps(data))
    reason = refused(tmp_path)
    assert "different request" in reason or "envelope is not valid" in reason


def test_an_artifact_that_does_not_match_its_hash_or_size_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    (tmp_path / "artifact-0.bin").write_bytes(b"swapped after hashing")
    assert "does not match its hash" in refused(tmp_path)
    write_result(tmp_path, 0, make_result(OP0))
    edit_result(tmp_path, 0, artifact={**json.loads((tmp_path / "result-0.json").read_text())["artifact"], "size": 3})
    assert "does not match its hash" in refused(tmp_path)


def test_an_artifact_with_no_description_or_a_description_with_no_artifact_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    (tmp_path / "artifact-0.bin").unlink()
    assert "do not go together" in refused(tmp_path)
    write_result(tmp_path, 0, make_result(OP0))
    edit_result(tmp_path, 0, artifact=None)
    assert "do not go together" in refused(tmp_path)


def test_an_artifact_with_no_result_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    (tmp_path / "artifact-1.bin").write_bytes(b"orphan")
    assert "no result" in refused(tmp_path)


def test_an_artifact_that_names_a_different_file_is_refused(tmp_path: Path) -> None:
    write_result(tmp_path, 0, make_result(OP0))
    data = json.loads((tmp_path / "result-0.json").read_text())["artifact"]
    edit_result(tmp_path, 0, artifact={**data, "file": "artifact-1.bin"})
    assert "different file" in refused(tmp_path)


def test_a_credential_in_a_result_or_an_artifact_refuses_the_directory_without_naming_it(tmp_path: Path) -> None:
    guard = LeakGuard([SECRET])
    write_result(tmp_path, 0, make_result(OP0, f"echoed {SECRET}"))
    reason = refused(tmp_path, guard=guard)
    assert "a credential value was found" in reason and SECRET not in reason
    clean = tmp_path / "clean"
    clean.mkdir()
    write_result(clean, 0, make_result(OP0, "nothing"))
    (clean / "result-0.json").write_text(
        (clean / "result-0.json").read_text().replace('"redactions"', f'"note": "{SECRET}", "redactions"')
    )
    assert "a credential value was found in a result file" in refused(clean, guard=guard)


def test_an_unreadable_directory_is_refused(tmp_path: Path) -> None:
    assert "could not be read" in refused(tmp_path / "missing")
