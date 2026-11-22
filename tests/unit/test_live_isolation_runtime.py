"""M6, D-E38: the firewall the container builds, the self-test that proves it, and the container command that holds it all. These test the
logic with no container: a real container is exercised by the `container` tests (`tests/container`), which need Docker."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from scopedagent.errors import ErrorCode, LiveFailed, LiveRefused
from scopedagent.live import isolation, runtime
from scopedagent.live.isolation import (
    FORBIDDEN,
    OUTPUT_CHECK,
    apply_rules,
    can_write,
    drop_privileges,
    effective_capabilities,
    gateway_address,
    rule_commands,
    rules_permit,
    self_test,
)
from scopedagent.live.protocol import AllowedPair, Job, Proof, ProofCheck
from scopedagent.live.runtime import DockerRuntime, DockerSession, docker_command, validate_image

pytestmark = pytest.mark.milestone("M6")

V4 = AllowedPair(address="93.184.216.34", port=443)
V6 = AllowedPair(address="2606:4700:4700::1111", port=8443)
DIGEST = "sha256:" + "a" * 64
IMAGE = f"registry.example.invalid/scopedagent/collector@{DIGEST}"


# ---------------------------------------------------------------------------------------------- the rules ----
def test_the_firewall_is_default_deny_both_ways_then_loopback_then_replies_then_exactly_the_pairs_then_reject() -> None:
    commands = rule_commands([V4, V6])
    flat = [" ".join(c) for c in commands]
    for tool in ("iptables", "ip6tables"):
        mine = [c for c in flat if c.startswith(tool + " ")]
        assert mine[:4] == [f"{tool} -F", f"{tool} -P INPUT DROP", f"{tool} -P FORWARD DROP", f"{tool} -P OUTPUT DROP"]
        assert f"{tool} -A OUTPUT -o lo -j ACCEPT" in mine and f"{tool} -A INPUT -i lo -j ACCEPT" in mine
        assert f"{tool} -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" in mine
        assert mine[-1] == f"{tool} -A OUTPUT -j REJECT"
    assert "iptables -A OUTPUT -d 93.184.216.34/32 -p tcp --dport 443 -j ACCEPT" in flat
    assert "ip6tables -A OUTPUT -d 2606:4700:4700::1111/128 -p tcp --dport 8443 -j ACCEPT" in flat
    accepts = [c for c in flat if "-d " in c and "ACCEPT" in c]
    assert len(accepts) == 2  # nothing is permitted but the two pairs


def test_with_no_pairs_nothing_leaves_at_all() -> None:
    flat = [" ".join(c) for c in rule_commands([])]
    assert not [c for c in flat if "-d " in c and "ACCEPT" in c]
    assert flat[-1] == "ip6tables -A OUTPUT -j REJECT" and "iptables -P OUTPUT DROP" in flat


def test_a_pair_is_normalised_so_one_spelling_is_one_rule() -> None:
    commands = rule_commands([AllowedPair(address="2606:4700:4700:0:0:0:0:1111", port=443)])
    assert [
        "ip6tables",
        "-A",
        "OUTPUT",
        "-d",
        "2606:4700:4700::1111/128",
        "-p",
        "tcp",
        "--dport",
        "443",
        "-j",
        "ACCEPT",
    ] in commands


def test_applying_runs_every_command_in_order_and_stops_at_the_first_failure() -> None:
    seen: list[list[str]] = []

    def run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        seen.append(list(argv))
        return subprocess.CompletedProcess(list(argv), 0, "", "")

    apply_rules([V4], run)
    assert seen == rule_commands([V4])

    calls: list[list[str]] = []

    def failing(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        return subprocess.CompletedProcess(list(argv), 0 if len(calls) < 3 else 1, "", "")

    with pytest.raises(RuntimeError, match="a firewall command failed"):
        apply_rules([V4], failing)
    assert len(calls) == 3


OUTPUT_RULES = """-P OUTPUT DROP
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -d 93.184.216.34/32 -p tcp -m tcp --dport 443 -j ACCEPT
-A OUTPUT -d 10.0.0.10/32 -p tcp -m tcp --dport 80 -j ACCEPT
-A OUTPUT -j REJECT --reject-with icmp-port-unreachable
"""


def test_the_rules_are_read_for_exactly_the_pair() -> None:
    assert rules_permit(OUTPUT_RULES, V4)
    assert not rules_permit(OUTPUT_RULES, AllowedPair(address="93.184.216.34", port=80))
    assert not rules_permit(OUTPUT_RULES, AllowedPair(address="93.184.216.35", port=443))
    assert not rules_permit(OUTPUT_RULES, AllowedPair(address="10.0.0.1", port=80))  # 10.0.0.10 is not 10.0.0.1
    assert rules_permit(OUTPUT_RULES, AllowedPair(address="10.0.0.10", port=80))
    assert not rules_permit("", V4)
    assert not rules_permit("-A OUTPUT -d 93.184.216.34/32 -p tcp -m tcp --dport 443 -j DROP\n", V4)
    assert not rules_permit("-A INPUT -d 93.184.216.34/32 -p tcp -m tcp --dport 443 -j ACCEPT\n", V4)
    assert not rules_permit("-A OUTPUT -d 93.184.216.34/32 -p tcp -m tcp --dport 4430 -j ACCEPT\n", V4)


def test_the_gateway_is_read_from_the_route_table() -> None:
    table = "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t0100A8C0\t0003\neth0\t0000A8C0\t00000000\t0001\n"
    assert gateway_address(table) == "192.168.0.1"
    assert gateway_address("Iface\tDestination\tGateway\n") is None
    assert gateway_address("") is None
    assert gateway_address("Iface\nlo\t00000000\t00000000\n") is None  # a default route with no gateway


# --------------------------------------------------------------------------------------------- self-test ----
def refused(address: str, port: int, timeout: float) -> object:
    raise ConnectionRefusedError("blocked")


def no_dns(host: str) -> object:
    raise OSError("no resolver")


def run_self_test(**over: Any) -> list[ProofCheck]:
    args: dict[str, Any] = {
        "rules_text": OUTPUT_RULES,
        "route_table": "",
        "connect": refused,
        "resolve": no_dns,
        "uid": lambda: 65534,
        "effective_caps": "0000000000000000",
    }
    args.update(over)
    return self_test([V4], **args)


def test_a_container_that_is_isolated_passes_every_check() -> None:
    checks = run_self_test()
    assert all(c.passed for c in checks), [c for c in checks if not c.passed]
    names = [c.name for c in checks]
    assert len([n for n in names if n.startswith("cannot reach")]) == len(FORBIDDEN)
    assert "has no name resolution" in names and "the rules permit 93.184.216.34:443" in names
    assert "runs unprivileged with no capability" in names


def test_the_output_directory_check_is_present_only_when_it_was_probed_and_fails_when_it_is_not_writable() -> None:
    assert OUTPUT_CHECK not in [c.name for c in run_self_test()]
    good = [c for c in run_self_test(output_writable=True) if c.name == OUTPUT_CHECK]
    bad = [c for c in run_self_test(output_writable=False) if c.name == OUTPUT_CHECK]
    assert [c.passed for c in good] == [True] and [c.passed for c in bad] == [False]
    assert "VM" in OUTPUT_CHECK and "home" in OUTPUT_CHECK  # the failure names the usual cause and its cure
    assert "not writable" in bad[0].detail and "written" in good[0].detail


def test_can_write_leaves_nothing_behind_and_says_no_for_a_directory_it_cannot_use(tmp_path: Path) -> None:
    assert can_write(tmp_path) is True and list(tmp_path.iterdir()) == []
    assert can_write(tmp_path / "missing") is False
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        assert can_write(locked) is (os.geteuid() == 0)  # root can write anywhere; anyone else cannot
    finally:
        locked.chmod(0o700)


def test_every_forbidden_destination_is_tried_including_the_metadata_address_and_the_gateway() -> None:
    tried: list[tuple[str, int]] = []

    def record(address: str, port: int, timeout: float) -> object:
        tried.append((address, port))
        raise OSError("blocked")

    run_self_test(connect=record, route_table="Iface\tDestination\tGateway\neth0\t00000000\t0100A8C0\n")
    addresses = {a for a, _ in tried}
    assert {
        "192.0.2.1",
        "10.255.255.254",
        "172.31.255.254",
        "192.168.255.254",
        "169.254.169.254",
        "2001:db8::1",
        "192.168.0.1",
    } <= addresses


class Reached:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_a_connection_that_succeeds_fails_the_proof_and_is_closed() -> None:
    reached = Reached()
    checks = run_self_test(connect=lambda a, p, t: reached)
    failed = [c for c in checks if not c.passed]
    assert len(failed) == len(FORBIDDEN) and reached.closed
    assert all(c.name.startswith("cannot reach") and c.detail == "the connection succeeded" for c in failed)


def test_one_forbidden_address_that_answers_is_enough_to_fail() -> None:
    def connect(address: str, port: int, timeout: float) -> object:
        if address == "169.254.169.254":
            return Reached()
        raise OSError("blocked")

    failed = [c for c in run_self_test(connect=connect) if not c.passed]
    assert [c.name for c in failed] == ["cannot reach the cloud metadata address"]


def test_a_name_that_resolves_fails_the_proof() -> None:
    failed = [c for c in run_self_test(resolve=lambda host: [("x",)]) if not c.passed]
    assert [c.name for c in failed] == ["has no name resolution"]


def test_a_pinned_pair_the_rules_do_not_permit_fails_the_proof() -> None:
    checks = self_test(
        [V4, V6], rules_text=OUTPUT_RULES, connect=refused, resolve=no_dns, uid=lambda: 1, effective_caps="0"
    )
    failed = [c.name for c in checks if not c.passed]
    assert failed == ["the rules permit 2606:4700:4700::1111:8443"]


def test_running_as_root_or_with_any_capability_fails_the_proof() -> None:
    assert [c.name for c in run_self_test(uid=lambda: 0) if not c.passed] == ["runs unprivileged with no capability"]
    for caps in ("0000000000001000", "00000000a80425fb", "ffffffffffffffff"):
        assert [c.name for c in run_self_test(effective_caps=caps) if not c.passed] == [
            "runs unprivileged with no capability"
        ]
    assert [c.name for c in run_self_test(effective_caps="0") if not c.passed] == []
    assert [c.name for c in run_self_test(effective_caps="") if not c.passed] == []


def test_effective_capabilities_are_read_from_the_status_text() -> None:
    status = "Name:\tpython\nCapPrm:\t0000000000000000\nCapEff:\t00000000a80425fb\nCapBnd:\tffffffffffffffff\n"
    assert effective_capabilities(status) == "00000000a80425fb"
    assert effective_capabilities("Name:\tx\n") == ""


def test_dropping_privileges_clears_groups_sets_gid_then_uid_and_checks_the_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(os, "setgroups", lambda g: calls.append(("groups", list(g))))
    monkeypatch.setattr(os, "setgid", lambda g: calls.append(("gid", g)))
    monkeypatch.setattr(os, "setuid", lambda u: calls.append(("uid", u)))
    monkeypatch.setattr(os, "getuid", lambda: 65534)
    monkeypatch.setattr(os, "geteuid", lambda: 65534)
    drop_privileges()
    assert calls == [("groups", []), ("gid", 65534), ("uid", 65534)]  # the gid is set while it still may be


# ----------------------------------------------------------------------------------------- the command ----
def flags(command: list[str]) -> str:
    return " ".join(command)


def test_the_container_command_is_the_whole_security_posture() -> None:
    command = docker_command(IMAGE, Path("/tmp/out"), "scopedagent-1", ["ORDERS_A_TOKEN", "BOT_KEY"])
    text = flags(command)
    for required in (
        "run --rm -i", "--read-only", "--security-opt no-new-privileges", "--cap-drop ALL",
        "--cap-add NET_ADMIN", "--cap-add SETUID", "--cap-add SETGID", "--memory 256m", "--memory-swap 256m",
        "--pids-limit 64", "--cpus 1", "--dns 127.0.0.1", "--tmpfs /tmp:rw,noexec,nosuid,size=64m",
        "-v /tmp/out:/out:rw", f"--entrypoint python {IMAGE} -m scopedagent.live.isolation",
    ):  # fmt: skip
        assert required in text, required
    assert command.count("--cap-add") == 3
    assert command.count("-v") == 1  # one directory is mounted and it is the output
    for forbidden in (
        "--privileged",
        "--network host",
        "--net host",
        "--pid host",
        "--cap-add ALL",
        "--cap-add SYS_ADMIN",
        "--device",
        "docker.sock",
        "--volumes-from",
        "--add-host",
        "-p ",
    ):
        assert forbidden not in text, forbidden


def test_a_credential_is_passed_by_name_so_its_value_is_in_no_argument() -> None:
    command = docker_command(IMAGE, Path("/o"), "n", ["ORDERS_A_TOKEN"])
    assert command[command.index("-e") + 1] == "ORDERS_A_TOKEN" and "=" not in command[command.index("-e") + 1]
    assert flags(docker_command(IMAGE, Path("/o"), "n", [])).count("-e ") == 0


@pytest.mark.parametrize(
    "image",
    [
        "",
        "collector",
        "collector:latest",
        "collector:1.0",
        "registry/collector",
        f"collector@sha256:{'a' * 63}",
        f"collector@sha256:{'a' * 65}",
        f"collector@sha256:{'A' * 64}",
        f"collector@sha1:{'a' * 40}",
        f"sha256:{'a' * 63}",
        f"sha256:{'a' * 65}",
        f"sha256:{'A' * 64}",
        f"sha256:{'g' * 64}",
        f"-sha256:{'a' * 64}",
        f"sha256:{'a' * 64} --privileged",
        f"sha256:{'a' * 64}\n",
        f" sha256:{'a' * 64}",
        "sha256",
        f"Collector@{DIGEST}",
        f"col lector@{DIGEST}",
        f"-v/:/x@{DIGEST}",
        f"a@{DIGEST}\n",
        f"a@{DIGEST} --privileged",
    ],
)
def test_an_image_that_is_not_pinned_by_digest_is_refused(image: str) -> None:
    with pytest.raises(LiveRefused) as caught:
        validate_image(image)
    assert caught.value.code is ErrorCode.LIVE_001 and "pinned by digest" in str(caught.value)
    with pytest.raises(LiveRefused):
        docker_command(image, Path("/o"), "n", [])


@pytest.mark.parametrize(
    "image", [IMAGE, f"a@{DIGEST}", f"localhost:5000/team/collector-1.0@{DIGEST}", f"ghcr.io/o/r@{DIGEST}", DIGEST]
)
def test_a_digest_pinned_image_is_accepted(image: str) -> None:
    assert validate_image(image) == image


def test_a_bare_image_id_is_passed_to_docker_as_it_is_and_never_as_a_name_to_pull() -> None:
    command = docker_command(DIGEST, Path("/o"), "n", [])
    assert command.count(DIGEST) == 1 and "@" not in DIGEST
    assert command.index(DIGEST) > command.index("--entrypoint")  # an operand of `docker run`, after every option


# -------------------------------------------------------------------------------- the runtime and session ----
def test_a_machine_without_docker_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime.shutil, "which", lambda name: None)
    with pytest.raises(LiveFailed) as caught:
        DockerRuntime.check_available()
    assert caught.value.code is ErrorCode.LIVE_001 and "`docker` was not found" in str(caught.value)


def test_a_docker_that_is_not_running_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime.shutil, "which", lambda name: "/usr/bin/docker")
    for result in (
        subprocess.CompletedProcess([], 1, "", "cannot connect"),
        subprocess.CompletedProcess([], 0, "  \n", ""),
    ):
        monkeypatch.setattr(runtime.subprocess, "run", lambda *a, _r=result, **k: _r)
        with pytest.raises(LiveFailed) as caught:
            DockerRuntime.check_available()
        assert caught.value.code is ErrorCode.LIVE_001 and "running container runtime" in str(caught.value)


def test_a_running_docker_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "29.1.0\n", ""))
    DockerRuntime.check_available()


def test_the_runtime_refuses_an_unpinned_image_when_it_is_built() -> None:
    with pytest.raises(LiveRefused):
        DockerRuntime("collector:latest")
    assert DockerRuntime(IMAGE)


class FakeProcess:
    """Just enough of a Popen: a text stdin we can read back, and a stdout that is the read end of a pipe."""

    def __init__(self, reply: str = "") -> None:
        read_fd, write_fd = os.pipe()
        self.stdout = os.fdopen(read_fd, "r")
        self._writer = os.fdopen(write_fd, "w")
        if reply:
            self._writer.write(reply)
            self._writer.flush()
        self.stdin: Any = io.StringIO()
        self.code = 0
        self.timeout = False
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("docker", timeout or 0)
        return self.code

    def kill(self) -> None:
        self.killed = True

    def close(self) -> None:
        self._writer.close()
        self.stdout.close()


@pytest.fixture
def process() -> Any:
    made: list[FakeProcess] = []

    def make(reply: str = "") -> FakeProcess:
        made.append(FakeProcess(reply))
        return made[-1]

    yield make
    for fake in made:
        fake.close()


def good_proof() -> Proof:
    return Proof(allowed=[V4], checks=[ProofCheck(name="cannot reach x", passed=True, detail="blocked")])


def test_the_session_sends_the_allow_list_and_reads_one_proof_line(process: Any) -> None:
    fake = process(good_proof().model_dump_json() + "\n")
    session = DockerSession(fake, Path("/o"), "n")
    assert session.exchange_proof([V4]) == good_proof()
    sent = fake.stdin.getvalue()
    assert sent.endswith("\n") and sent.count("\n") == 1 and '"allow"' in sent and '"93.184.216.34"' in sent


@pytest.mark.parametrize(
    "reply",
    [
        "not json\n",
        "{}\n",
        '{"version": 1}\n',
        good_proof().model_dump_json().replace('"passed":true', '"passed":"yes"') + "\n",
    ],
)
def test_a_proof_that_is_not_valid_is_refused(process: Any, reply: str) -> None:
    with pytest.raises(LiveFailed) as caught:
        DockerSession(process(reply), Path("/o"), "n").exchange_proof([V4])
    assert caught.value.code is ErrorCode.LIVE_003


def test_a_container_that_says_nothing_is_given_up_on(process: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime, "PROOF_TIMEOUT_SECONDS", 0.05)
    with pytest.raises(LiveFailed, match="did not report"):
        DockerSession(process(""), Path("/o"), "n").exchange_proof([V4])


def test_the_wait_for_the_proof_is_bounded_to_a_minute_or_two() -> None:
    assert 1 <= runtime.PROOF_TIMEOUT_SECONDS <= 120


def test_a_proof_that_is_too_long_is_refused(process: Any) -> None:
    with pytest.raises(LiveFailed, match="too long"):
        DockerSession(process("x" * (runtime.MAX_PROOF_BYTES + 10) + "\n"), Path("/o"), "n").exchange_proof([V4])


def test_the_job_is_sent_as_one_line_and_the_input_is_closed(process: Any) -> None:
    job = Job(max_response_bytes=1024, per_request_timeout_seconds=5, requests_per_second=2, operations=[])
    fake = process()
    captured: list[str] = []

    class Capture(io.StringIO):
        def close(self) -> None:
            captured.append(self.getvalue())
            super().close()

    fake.stdin = Capture()
    DockerSession(fake, Path("/o"), "n").send_job(job)
    assert fake.stdin.closed and len(captured) == 1
    assert captured[0].count("\n") == 1 and Job.model_validate_json(captured[0]) == job


def test_finish_returns_the_exit_status(process: Any) -> None:
    fake = process()
    fake.code = 4
    assert DockerSession(fake, Path("/o"), "n").finish() == 4


def test_a_collector_that_runs_past_its_wall_clock_limit_is_killed(
    process: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = process()
    fake.timeout = True
    killed: list[list[str]] = []
    monkeypatch.setattr(
        runtime.subprocess, "run", lambda argv, **k: killed.append(list(argv)) or subprocess.CompletedProcess(argv, 0)
    )
    with pytest.raises(LiveFailed) as caught:
        DockerSession(fake, Path("/o"), "scopedagent-9").finish()
    assert caught.value.code is ErrorCode.LIVE_004 and killed == [["docker", "kill", "scopedagent-9"]] and fake.killed


def test_aborting_closes_the_input_and_kills_a_container_that_will_not_stop(
    process: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = process()
    DockerSession(fake, Path("/o"), "n").abort()
    assert fake.stdin.closed and not fake.killed
    stuck = process()
    stuck.timeout = True
    killed: list[list[str]] = []
    monkeypatch.setattr(
        runtime.subprocess, "run", lambda argv, **k: killed.append(list(argv)) or subprocess.CompletedProcess(argv, 0)
    )
    DockerSession(stuck, Path("/o"), "scopedagent-3").abort()
    assert killed == [["docker", "kill", "scopedagent-3"]] and stuck.killed


def test_starting_runs_the_documented_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    started: list[Any] = []
    monkeypatch.setattr(DockerRuntime, "check_available", staticmethod(lambda: None))

    class Popen:
        def __init__(self, argv: list[str], **kwargs: Any) -> None:
            started.append((argv, kwargs))
            self.stdin = self.stdout = None

    monkeypatch.setattr(runtime.subprocess, "Popen", Popen)
    session = DockerRuntime(IMAGE).start(credential_envs=["BOT_KEY"], out_dir=tmp_path)
    argv, kwargs = started[0]
    assert argv[:3] == ["docker", "run", "--rm"] and f"{tmp_path}:/out:rw" in argv and "BOT_KEY" in argv
    assert (
        kwargs["stdin"] == subprocess.PIPE
        and kwargs["stdout"] == subprocess.PIPE
        and kwargs["stderr"] == subprocess.DEVNULL
    )
    assert session.out_dir == tmp_path


def test_the_real_command_runner_runs_a_command_and_returns_what_it_printed() -> None:
    result = isolation._run([sys.executable, "-c", "print('ok')"])
    assert result.returncode == 0 and result.stdout == "ok\n"


@pytest.mark.loopback
def test_the_real_connect_reaches_a_loopback_listener() -> None:
    import socket  # noqa: PLC0415

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        connection = isolation._default_connect("127.0.0.1", listener.getsockname()[1], 2.0)
        connection.close()  # type: ignore[attr-defined]
    finally:
        listener.close()


def test_a_connection_object_without_a_close_method_does_not_break_the_self_test() -> None:
    checks = run_self_test(connect=lambda a, p, t: object())
    assert len([c for c in checks if not c.passed]) == len(FORBIDDEN)


def test_a_controller_message_is_read_one_line_at_a_time_and_a_long_one_is_refused() -> None:
    assert isolation._read_line(io.StringIO('{"a": 1}\nsecond\n'), 100) == '{"a": 1}\n'
    with pytest.raises(ValueError, match="too long"):
        isolation._read_line(io.StringIO("x" * 50 + "\n"), 10)


def test_aborting_after_the_input_was_already_closed_is_harmless(process: Any) -> None:
    fake = process()
    fake.stdin.close()
    DockerSession(fake, Path("/o"), "n").abort()
    assert fake.stdin.closed and not fake.killed
