"""Egress isolation inside the container, and the proof of it (D-E38, docs/remote-live-design.md 4.4).

The container starts with the capabilities it needs to install a firewall and nothing else. `main()` installs a default-deny OUTPUT
policy that permits only the pinned `IP:port` pairs (and loopback), runs a self-test that must show forbidden destinations
unreachable and the pinned ones permitted by the rules, drops every privilege, and only then tells the controller what it found. The
controller refuses to continue unless every check passed. There is no flag that says "trust me, I am isolated".

This module runs as root only until `drop_privileges()`; the collector never does.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import IO

from scopedagent.live.protocol import MAX_PROOF_BYTES, AllowedPair, Job, Proof, ProofCheck

Run = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
Connect = Callable[[str, int, float], object]
NOBODY = 65534
SELF_TEST_TIMEOUT = 2.0
OUTPUT_CHECK = "can write to the output directory (VM Docker: data dir under home)"

# Destinations the container must NOT be able to reach (RFC 5737 / RFC 3849 documentation addresses, a private range and the
# cloud metadata address). None of them is a real service: a connection that succeeds means the firewall is not doing its job.
FORBIDDEN: tuple[tuple[str, str, int], ...] = (
    ("a documentation address (IPv4)", "192.0.2.1", 80),
    ("a private range (10/8)", "10.255.255.254", 80),
    ("a private range (172.16/12)", "172.31.255.254", 80),
    ("a private range (192.168/16)", "192.168.255.254", 80),
    ("the cloud metadata address", "169.254.169.254", 80),
    ("a documentation address (IPv6)", "2001:db8::1", 80),
)


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), capture_output=True, text=True, check=False, timeout=15)  # noqa: S603


def _tool(address: str) -> str:
    return "ip6tables" if ipaddress.ip_address(address).version == 6 else "iptables"


def rule_commands(pairs: Sequence[AllowedPair]) -> list[list[str]]:
    """The exact firewall commands for an allow-list. Default deny both ways, loopback, replies to our own connections, then each pair."""
    commands: list[list[str]] = []
    for tool in ("iptables", "ip6tables"):
        commands += [
            [tool, "-F"],
            [tool, "-P", "INPUT", "DROP"],
            [tool, "-P", "FORWARD", "DROP"],
            [tool, "-P", "OUTPUT", "DROP"],
            [tool, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            [tool, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            [tool, "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ]
    for pair in pairs:
        address = str(ipaddress.ip_address(pair.address))
        mask = "/128" if ":" in address else "/32"
        commands.append(
            [
                _tool(address),
                "-A",
                "OUTPUT",
                "-d",
                address + mask,
                "-p",
                "tcp",
                "--dport",
                str(pair.port),
                "-j",
                "ACCEPT",
            ]
        )
    for tool in ("iptables", "ip6tables"):
        commands.append([tool, "-A", "OUTPUT", "-j", "REJECT"])
    return commands


def apply_rules(pairs: Sequence[AllowedPair], run: Run = _run) -> None:
    for command in rule_commands(pairs):
        result = run(command)
        if result.returncode != 0:
            raise RuntimeError(f"a firewall command failed: {' '.join(command[:4])}")


def rules_permit(rules_text: str, pair: AllowedPair) -> bool:
    """Whether `iptables -S OUTPUT` text holds an ACCEPT for exactly this pair (read, not tried: nothing is contacted)."""
    address = str(ipaddress.ip_address(pair.address))
    mask = "/128" if ":" in address else "/32"
    needle = f"-d {address}{mask}"
    return any(
        line.startswith("-A OUTPUT")
        and needle in line
        and f"--dport {pair.port} " in line + " "
        and "-j ACCEPT" in line
        for line in rules_text.splitlines()
    )


def _default_connect(address: str, port: int, timeout: float) -> object:
    return socket.create_connection((address, port), timeout=timeout)


def gateway_address(route_table: str) -> str | None:
    """The default gateway from the text of /proc/net/route, or None."""
    for line in route_table.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "00000000" and fields[2] != "00000000":
            return str(ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(fields[2]), "little")))
    return None


def self_test(
    pairs: Sequence[AllowedPair],
    *,
    rules_text: str,
    route_table: str = "",
    connect: Connect = _default_connect,
    resolve: Callable[[str], object] = lambda host: socket.getaddrinfo(host, None),
    uid: Callable[[], int] = os.getuid,
    effective_caps: str = "",
    output_writable: bool | None = None,
) -> list[ProofCheck]:
    """Every check the controller will insist on. A check passes only when the thing that must not happen did not."""
    checks: list[ProofCheck] = []
    targets = list(FORBIDDEN)
    gateway = gateway_address(route_table)
    if gateway is not None:
        targets.append(("the host's gateway address", gateway, 80))
    for name, address, port in targets:
        try:
            connection = connect(address, port, SELF_TEST_TIMEOUT)
        except OSError as exc:
            checks.append(ProofCheck(name=f"cannot reach {name}", passed=True, detail=type(exc).__name__))
        else:
            close = getattr(connection, "close", None)
            if callable(close):
                close()
            checks.append(ProofCheck(name=f"cannot reach {name}", passed=False, detail="the connection succeeded"))
    try:
        resolve("example.com")
    except OSError:
        checks.append(ProofCheck(name="has no name resolution", passed=True, detail="the lookup failed"))
    else:
        checks.append(ProofCheck(name="has no name resolution", passed=False, detail="a name resolved"))
    for pair in pairs:
        permitted = rules_permit(rules_text, pair)
        checks.append(
            ProofCheck(
                name=f"the rules permit {pair.address}:{pair.port}",
                passed=permitted,
                detail="an ACCEPT rule for exactly this pair" if permitted else "no ACCEPT rule for this pair",
            )
        )
    checks.append(
        ProofCheck(
            name="runs unprivileged with no capability",
            passed=uid() != 0 and effective_caps.strip().strip("0") == "",
            detail=f"uid {uid()}, capabilities {effective_caps or 'unknown'}",
        )
    )
    if output_writable is not None:
        checks.append(
            ProofCheck(
                name=OUTPUT_CHECK,
                passed=output_writable,
                detail="a probe file was written and removed"
                if output_writable
                else "not writable: with Docker in a VM (Colima, Docker Desktop) keep the data directory under your home",
            )
        )
    return checks


def can_write(directory: Path) -> bool:
    """Whether the collector (already unprivileged) can create a file in `directory`. The probe is removed again."""
    probe = directory / ".writable-probe"
    try:
        probe.write_bytes(b"")
        probe.unlink()
    except OSError:
        return False
    return True


def effective_capabilities(status_text: str) -> str:
    """The CapEff hexadecimal field of /proc/self/status ('' when absent)."""
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            return line.split(":", 1)[1].strip()
    return ""


def drop_privileges(uid: int = NOBODY) -> None:
    """Become an unprivileged user. Changing from root to a non-zero uid clears every capability."""
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    if os.getuid() == 0 or os.geteuid() == 0:  # pragma: no cover - setuid would have raised
        raise RuntimeError("could not drop privileges")


def _read_line(stream: IO[str], limit: int) -> str:
    line = stream.readline(limit + 1)
    if len(line) > limit:
        raise ValueError("a controller message is too long")
    return line


def main(stdin: IO[str], stdout: IO[str], out_dir: Path) -> int:  # pragma: no cover - runs only inside the container
    """The container entrypoint: rules, self-test, drop privileges, proof, wait for the job, collect."""
    from scopedagent.live.collector import run_job  # noqa: PLC0415

    message = json.loads(_read_line(stdin, MAX_PROOF_BYTES))
    pairs = [AllowedPair.model_validate(p) for p in message["allow"]]
    apply_rules(pairs)
    rules = _run(["iptables", "-S", "OUTPUT"]).stdout + _run(["ip6tables", "-S", "OUTPUT"]).stdout
    route = Path("/proc/net/route").read_text(encoding="utf-8")
    drop_privileges()
    caps = effective_capabilities(Path("/proc/self/status").read_text(encoding="utf-8"))
    proof = Proof(
        allowed=pairs,
        checks=self_test(
            pairs, rules_text=rules, route_table=route, effective_caps=caps, output_writable=can_write(out_dir)
        ),
    )
    stdout.write(proof.model_dump_json() + "\n")
    stdout.flush()
    line = _read_line(stdin, 4 * 1024 * 1024)
    if not line.strip():
        return 3
    job = Job.model_validate(json.loads(line))
    if {(op.address, op.port) for op in job.operations} - {(p.address, p.port) for p in pairs}:
        return 4  # an operation outside the allow-list the firewall was built from
    run_job(job, out_dir)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.stdin, sys.stdout, Path("/out")))
