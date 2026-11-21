"""Mutation check: does the test suite notice a deliberate security bug?

    uv run python tools/mutation.py                 # baseline, then every mutant
    uv run python tools/mutation.py NAME [NAME...]  # only the named mutants

The repo is copied to a scratch directory and ONE bug is injected into the copy at a time (the real tree is never
modified). A mutant is KILLED when at least one test fails, SURVIVED when every test still passes, NOAPPLY when the
patch no longer matches the source (the table is stale). The unmutated baseline must be green first: a red baseline
would make every mutant look killed for the wrong reason.

Exit status: 0 when every mutant is killed, 1 when one survived, 2 when one did not apply or the baseline is red.

Known limits: killing a mutant shows a test notices THAT bug, not that no other bug exists. An "equivalent" mutant (one
that cannot change observable behaviour) can never be killed; none is kept here, and a comment says where two layers
guard the same property and so are removed together. One deliberate omission: removing the regular-file check in
`load_scope` would make the FIFO test block forever, so it is covered by that test but not mutated.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = "src/scopedagent"
YML, SCP, AUZ, STM, OUT, ERR, LOG, SCH, CLI = (
    f"{SRC}/{n}.py"
    for n in ("strictyaml", "policy/scope", "policy/authorization", "domain/state_machine", "domain/outcome", "errors", "logs", "domain/schemas", "cli")
)  # fmt: skip
BUD, REP, ART, AUD, DBS, MOD, MIG = (
    f"{SRC}/{n}.py"
    for n in ("policy/budget", "storage/repositories", "storage/artifacts", "storage/audit", "storage/database", "domain/models", "storage/migrations/versions/0001_initial")
)  # fmt: skip

M: dict[str, list[tuple[str, str, str]]] = {
    # ---- the strict YAML loader ----------------------------------------------------------------
    # an alias event also carries an anchor name, so each check alone still refuses an alias (two layers): remove both
    "yaml_aliases_and_anchors_allowed": [(YML, "if self.check_event(yaml.events.AliasEvent):", "if False:"), (YML, 'if getattr(self.peek_event(), "anchor", None) is not None:', "if False:")],
    "yaml_anchors_allowed": [(YML, 'if getattr(self.peek_event(), "anchor", None) is not None:', "if False:")],
    "yaml_duplicate_keys_allowed": [(YML, "if key in seen:", "if False:")],
    "yaml_merge_keys_allowed": [(YML, 'if key_node.tag == "tag:yaml.org,2002:merge":', "if False:")],
    "yaml_non_string_keys_allowed": [(YML, "if not isinstance(key, str):", "if False:")],
    "yaml_depth_unlimited": [(YML, "if self._depth > MAX_DEPTH:", "if False:")],
    "yaml_depth_cap_off_by_one": [(YML, "MAX_DEPTH = 16", "MAX_DEPTH = 40")],
    "yaml_syntax_errors_called_forbidden": [(YML, '"syntax", "the text is not valid YAML', '"forbidden", "the text is not valid YAML')],
    "yaml_reader_errors_escape": [(YML, "loader = _Loader(text)  # the constructor", "pass  # the constructor")],
    # ---- hosts and paths -----------------------------------------------------------------------
    "host_non_text_accepted": [(SCP, "if not isinstance(raw, str):\n        raise ScopeError(ErrorCode.SCOPE_005", "if False:\n        raise ScopeError(ErrorCode.SCOPE_005")],
    "host_not_lowercased": [(SCP, "text = raw.lower()", "text = raw")],
    "host_trailing_dot_kept": [(SCP, "if text.endswith(\".\"):\n        text = text[:-1]", "if False:\n        text = text[:-1]")],
    "host_two_trailing_dots_stripped": [(SCP, "if text.endswith(\".\"):\n        text = text[:-1]", "text = text.rstrip(\".\")")],
    # the character class and the per-label rule both refuse a bad character (two layers): remove both
    "host_alphabet_unchecked": [(SCP, "if not _HOST_CHARS.fullmatch(text):", "if False:"), (SCP, "or not all(_LABEL.fullmatch(label) for label in labels)", "")],
    "host_single_label_allowed": [(SCP, "if len(labels) < 2 or", "if len(labels) < 1 or")],
    "host_length_unlimited": [(SCP, "or len(text) > MAX_HOST or", "or")],
    "host_max_length_off_by_one": [(SCP, "MAX_HOST = 253", "MAX_HOST = 254")],
    "host_numeric_tld_allowed": [(SCP, "if labels[-1].isdigit():", "if False:")],
    "host_idna_not_validated": [(SCP, 'label.encode("ascii").decode("idna")', "label")],
    "host_xn_prefix_ignored": [(SCP, 'if label.startswith("xn--"):', "if False:")],
    "path_chars_unchecked": [(SCP, "or not _PATH_CHARS.fullmatch(raw)", "")],
    "path_dot_segments_allowed": [(SCP, 'if segment in {".", ".."}:', "if False:")],
    "path_empty_segments_allowed": [(SCP, 'if segment == "" and index != len(segments) - 1:', "if False:")],
    "path_trailing_slash_refused": [(SCP, 'if segment == "" and index != len(segments) - 1:', 'if segment == "":')],
    "path_too_long_allowed": [(SCP, "len(raw) > MAX_PATH", "len(raw) > MAX_PATH + 1")],
    "path_limit_exclusive": [(SCP, "len(raw) > MAX_PATH", "len(raw) >= MAX_PATH")],
    "path_must_start_with_slash_dropped": [(SCP, '_PATH_CHARS = re.compile(r"/[A-Za-z0-9._~/-]*")', '_PATH_CHARS = re.compile(r"/?[A-Za-z0-9._~/-]*")')],
    # ---- the scope schema ----------------------------------------------------------------------
    "scope_unknown_keys_allowed": [(SCP, 'extra="forbid"', 'extra="ignore"')],
    "scope_type_coercion_allowed": [(SCP, "strict=True,", "strict=False,")],
    "scope_schemes_unchecked": [(SCP, "if not value or any(s not in _SCHEMES for s in value) or len(set(value)) != len(value):", "if False:")],
    "scope_ports_unchecked": [(SCP, "if any(not 1 <= p <= 65535 for p in value) or len(set(value)) != len(value):", "if False:")],
    "scope_port_range_off_by_one": [(SCP, "not 1 <= p <= 65535", "not 0 <= p <= 65536")],
    "scope_duplicate_paths_allowed": [(SCP, "if len(set(paths)) != len(paths):", "if False:")],
    "scope_several_schemes_and_ports_allowed": [(SCP, "if len(self.schemes) > 1 and len(self.ports) > 1:", "if False:")],
    "scope_engagement_id_unchecked": [(SCP, "if isinstance(value, str) and not _ENGAGEMENT_ID.fullmatch(value):", "if False:")],
    "scope_approval_ref_unchecked": [(SCP, "if isinstance(value, str) and not _APPROVAL_REF.fullmatch(value):", "if False:")],
    "scope_engagement_id_pattern_weakened": [(SCP, 'r"[a-z0-9][a-z0-9._-]{2,63}"', 'r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"')],
    "scope_expiry_pattern_unchecked": [(SCP, "if not _TIMESTAMP.fullmatch(value):", "if False:")],
    "scope_expiry_non_text_allowed": [(SCP, "if not isinstance(value, str):\n        raise ScopeValueError(ErrorCode.SCOPE_004", "if False:\n        raise ScopeValueError(ErrorCode.SCOPE_004")],
    "scope_follow_redirects_allowed": [(SCP, "        if value:\n            raise ScopeValueError(\n                ErrorCode.SCOPE_008", "        if False:\n            raise ScopeValueError(\n                ErrorCode.SCOPE_008")],
    "scope_duplicate_operations_allowed": [(SCP, "if len(set(value)) != len(value):\n            raise ScopeValueError(ErrorCode.SCOPE_003", "if False:\n            raise ScopeValueError(ErrorCode.SCOPE_003")],
    "scope_duplicate_endpoints_merged": [(SCP, "if key in seen:", "if False:")],
    "scope_tls_without_https_allowed": [(SCP, 'if "tls_metadata" in self.allowed_operations and not any("https" in e.schemes for e in self.allowed_targets):', "if False:")],
    "scope_http_without_paths_allowed": [(SCP, 'if "http_metadata" in self.allowed_operations and not any(e.allowed_paths for e in self.allowed_targets):', "if False:")],
    "scope_max_requests_ceiling_raised": [(SCP, "Field(ge=1, le=500)", "Field(ge=1, le=501)")],
    "scope_max_requests_floor_lowered": [(SCP, "Field(ge=1, le=500)", "Field(ge=0, le=500)")],
    "scope_parallelism_ceiling_raised": [(SCP, "Field(ge=1, le=4)", "Field(ge=1, le=5)")],
    "scope_parallelism_floor_lowered": [(SCP, "Field(ge=1, le=4)", "Field(ge=0, le=4)")],
    "scope_timeout_ceiling_raised": [(SCP, "Field(ge=1, le=30)", "Field(ge=1, le=31)")],
    "scope_timeout_floor_lowered": [(SCP, "Field(ge=1, le=30)", "Field(ge=0, le=30)")],
    "scope_response_bytes_ceiling_raised": [(SCP, "le=1_000_000", "le=1_000_001")],
    "scope_response_bytes_floor_lowered": [(SCP, "ge=1024", "ge=1023")],
    "scope_target_cap_raised": [(SCP, "Field(min_length=1, max_length=20)]\n    allowed_operations", "Field(min_length=1, max_length=21)]\n    allowed_operations")],
    "scope_port_cap_raised": [(SCP, "Field(min_length=1, max_length=8)", "Field(min_length=1, max_length=9)")],
    "scope_path_cap_raised": [(SCP, "Field(max_length=20)] = []", "Field(max_length=21)] = []")],
    "scope_default_mode_is_live": [(SCP, 'mode: Literal["offline", "live"] = "offline"', 'mode: Literal["offline", "live"] = "live"')],
    "scope_default_redirects_on": [(SCP, "follow_redirects: bool = False", "follow_redirects: bool = True")],
    # ---- expiry, hash and size ---------------------------------------------------------------
    "expiry_boundary_inclusive": [(SCP, "if now >= expires_at:", "if now > expires_at:")],
    "expiry_not_checked": [(SCP, "    check_not_expired(config.expires_at, now)\n    if config.expires_at >", "    if config.expires_at >")],
    "expiry_horizon_raised": [(SCP, "MAX_EXPIRY_DAYS = 366", "MAX_EXPIRY_DAYS = 400")],
    "expiry_horizon_exclusive": [(SCP, "if config.expires_at > now + timedelta(days=MAX_EXPIRY_DAYS):", "if config.expires_at >= now + timedelta(days=MAX_EXPIRY_DAYS):")],
    "hash_ignores_key_order_off": [(SCP, "canonical = json.dumps(normalised(config), sort_keys=True,", "canonical = json.dumps(normalised(config), sort_keys=False,")],
    "hash_drops_defaults": [(SCP, '"max_parallelism": config.max_parallelism,', "")],
    "hash_drops_paths": [(SCP, '"allowed_paths": list(e.allowed_paths)', '"allowed_paths": []')],
    "hash_expiry_format_changed": [(SCP, 'astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")', 'astimezone(UTC).strftime("%Y-%m-%d")')],
    "hash_is_not_sha256": [(SCP, "hashlib.sha256(canonical.encode(\"ascii\")).hexdigest()", "hashlib.sha1(canonical.encode(\"ascii\")).hexdigest().ljust(64, \"0\")")],
    # two layers guard the size cap (parse_scope and load_scope): remove both
    "scope_size_cap_off": [(SCP, "if size > MAX_SCOPE_BYTES:", "if False:"), (SCP, "if len(raw) > MAX_SCOPE_BYTES:", "if False:")],
    "scope_size_cap_raised": [(SCP, "MAX_SCOPE_BYTES = 64 * 1024", "MAX_SCOPE_BYTES = 640 * 1024")],
    "error_constraints_become_type_errors": [(SCP, 'ErrorCode.SCOPE_007 if error["type"] in _CONSTRAINT_ERRORS else ErrorCode.SCOPE_003', 'ErrorCode.SCOPE_003')],
    "error_path_loses_indexes": [(SCP, 'parts += f"[{item}]" if isinstance(item, int)', 'parts += f".{item}" if isinstance(item, int)')],
    "error_code_of_validator_ignored": [(SCP, "return ScopeError(original.code, str(original), path=path)", "return ScopeError(ErrorCode.SCOPE_003, str(original), path=path)")],
    # ---- the plan ------------------------------------------------------------------------------
    "plan_dns_repeated_per_entry": [(SCP, 'if "dns_metadata" in allowed and entry.host not in seen_hosts:', 'if "dns_metadata" in allowed:')],
    "plan_dns_on_the_last_scheme_and_port": [(SCP, "entry.schemes[0], entry.ports[0], None", "entry.schemes[-1], entry.ports[-1], None")],
    "plan_tls_for_http_entries": [(SCP, 'if "tls_metadata" in allowed and "https" in entry.schemes:', 'if "tls_metadata" in allowed:')],
    "plan_ignores_allowed_operations": [(SCP, "allowed = set(config.allowed_operations)", 'allowed = {"dns_metadata", "tls_metadata", "http_metadata"}')],
    "plan_drops_ports_after_the_first": [(SCP, '"https", port, None) for port in entry.ports)', '"https", port, None) for port in entry.ports[:1])')],
    "plan_reverses_paths": [(SCP, 'for path in entry.allowed_paths\n', 'for path in reversed(entry.allowed_paths)\n')],
    # ---- authorization -------------------------------------------------------------------------
    "auth_live_allowed": [(AUZ, 'if loaded.config.mode != "offline":', "if False:")],
    "auth_changed_scope_allowed": [(AUZ, "or expected_sha256 != loaded.sha256", "")],
    "auth_missing_hash_allowed": [(AUZ, "if expected_sha256 is None or", "if False or")],
    "auth_expiry_not_rechecked": [(AUZ, "    check_not_expired(loaded.config.expires_at, now)", "    pass")],
    "auth_notice_weakened": [(AUZ, "not proof of authorization", "authorization")],
    # ---- state machines ------------------------------------------------------------------------
    "run_model_may_transition": [(STM, 'if actor.type is ActorType.MODEL:\n        raise StateError(ErrorCode.STATE_003, "the model may not change the state of a run")', "if False:\n        pass")],
    "run_worker_may_export_or_retry": [(STM, "if dst in HUMAN_ONLY_RUN_TARGETS and actor.type is not ActorType.HUMAN:", "if False:")],
    "run_export_not_human_only": [(STM, "HUMAN_ONLY_RUN_TARGETS = frozenset({_R.EXPORTED, _R.RETRIED})", "HUMAN_ONLY_RUN_TARGETS = frozenset({_R.RETRIED})")],
    "run_retry_not_human_only": [(STM, "HUMAN_ONLY_RUN_TARGETS = frozenset({_R.EXPORTED, _R.RETRIED})", "HUMAN_ONLY_RUN_TARGETS = frozenset({_R.EXPORTED})")],
    "run_may_skip_a_step": [(STM, "_R.CREATED: frozenset({_R.SCOPE_VALIDATED} | _OFF_RAMP)", "_R.CREATED: frozenset({_R.SCOPE_VALIDATED, _R.COLLECTING} | _OFF_RAMP)")],
    "run_failed_may_restart": [(STM, "_R.FAILED: frozenset({_R.RETRIED})", "_R.FAILED: frozenset({_R.RETRIED, _R.CREATED})")],
    "run_exported_is_not_final": [(STM, "_R.EXPORTED: frozenset(),", "_R.EXPORTED: frozenset({_R.FAILED}),")],
    "run_canceled_is_not_final": [(STM, "_R.CANCELED: frozenset(),", "_R.CANCELED: frozenset({_R.CREATED}),")],
    "run_review_cannot_be_canceled": [(STM, "_R.HUMAN_REVIEW: frozenset({_R.EXPORTED} | _OFF_RAMP)", "_R.HUMAN_REVIEW: frozenset({_R.EXPORTED})")],
    "run_terminal_states_incomplete": [(STM, "TERMINAL_RUN_STATES = frozenset({_R.EXPORTED, _R.FAILED, _R.CANCELED, _R.RETRIED})", "TERMINAL_RUN_STATES = frozenset({_R.EXPORTED, _R.CANCELED})")],
    "finding_model_may_transition": [(STM, 'if actor.type is ActorType.MODEL:\n        raise StateError(ErrorCode.STATE_003, "the model may not change the state of a finding")', "if False:\n        pass")],
    "finding_worker_may_validate": [(STM, "    if actor.type is not ActorType.HUMAN:\n        raise StateError(ErrorCode.STATE_003, f\"only a human reviewer", "    if False:\n        raise StateError(ErrorCode.STATE_003, f\"only a human reviewer")],
    "finding_blank_reviewer_allowed": [(STM, "if not actor.id.strip():", "if False:")],
    "finding_blank_reason_allowed": [(STM, "if not reason.strip():", "if False:")],
    "finding_no_evidence_allowed": [(STM, "if evidence_count < 1:", "if False:")],
    "finding_one_evidence_not_enough": [(STM, "if evidence_count < 1:", "if evidence_count < 2:")],
    "finding_false_positive_may_be_remediated": [(STM, "_F.FALSE_POSITIVE: frozenset(),", "_F.FALSE_POSITIVE: frozenset({_F.REMEDIATED}),")],
    "finding_may_skip_validation": [(STM, "_F.DRAFT: frozenset({_F.NEEDS_VALIDATION})", "_F.DRAFT: frozenset({_F.NEEDS_VALIDATION, _F.VALIDATED})")],
    "finding_verified_is_not_final": [(STM, "_F.VERIFIED: frozenset(),", "_F.VERIFIED: frozenset({_F.DRAFT}),")],
    "finding_review_data_not_needed_for_needs_validation_only": [(STM, "if dst is FindingStatus.NEEDS_VALIDATION:\n        return", "if False:\n        return")],
    "actor_type_not_validated": [(STM, "if not isinstance(self.type, ActorType):", "if False:")],
    # ---- coverage and exit codes ---------------------------------------------------------------
    "coverage_empty_plan_is_complete": [(OUT, "return self.planned > 0 and", "return")],
    "coverage_errors_ignored": [(OUT, "and self.ok == self.planned and not self.by_status", "and self.ok == self.planned")],
    "coverage_more_than_planned_is_complete": [(OUT, "self.ok == self.planned", "self.ok >= self.planned")],
    "coverage_ok_counted_as_error": [(OUT, "ok = counts.pop(ErrorStatus.OK, 0)", "ok = counts.get(ErrorStatus.OK, 0)")],
    "exit_incomplete_not_two": [(OUT, "if infrastructure_failure or not coverage.complete:", "if infrastructure_failure:")],
    "exit_failure_ignored": [(OUT, "if infrastructure_failure or not coverage.complete:", "if not coverage.complete:")],
    "exit_review_needs_two_drafts": [(OUT, "if drafts_needing_review > 0 else", "if drafts_needing_review > 1 else")],
    "exit_negative_drafts_allowed": [(OUT, "if drafts_needing_review < 0:", "if False:")],
    "exit_codes_renumbered": [(OUT, "INCOMPLETE = 2", "INCOMPLETE = 3")],
    "error_status_clean_added": [(OUT, 'ADAPTER_ERROR = "adapter_error"', 'ADAPTER_ERROR = "adapter_error"\n    CLEAN = "clean"')],
    "store_errors_exit_one": [(ERR, "class StoreError(ScopedAgentError):\n    exit_code = 2", "class StoreError(ScopedAgentError):\n    exit_code = 1")],
    "scope_errors_exit_two": [(ERR, "class ScopeError(ScopedAgentError):\n    exit_code = 1", "class ScopeError(ScopedAgentError):\n    exit_code = 2")],
    "budget_errors_exit_one": [(ERR, "class BudgetError(ScopedAgentError):\n    exit_code = 2", "class BudgetError(ScopedAgentError):\n    exit_code = 1")],
    "error_path_not_shown": [(ERR, 'where = f"{self.path}: " if self.path else ""', 'where = ""')],
    # ---- logging -------------------------------------------------------------------------------
    "log_control_characters_kept": [(LOG, 'return "".join(" " if unicodedata.category(ch) in _CONTROL else ch for ch in text)', "return text")],
    "log_unbounded": [(LOG, "text = str(value)[:limit]", "text = str(value)")],
    "log_message_not_cleaned": [(LOG, '"message": safe_text(record.getMessage()),', '"message": record.getMessage(),')],
    "log_secrets_not_redacted": [(LOG, "if _is_sensitive(key):", "if False:")],
    "log_hyphenated_names_not_normalised": [(LOG, 'lowered = name.lower().replace("-", "_")', "lowered = name.lower()")],
    "log_cookie_not_sensitive": [(LOG, '"authorization", "cookie",', '"authorization",')],
    "log_extras_not_cleaned": [(LOG, "payload[key] = safe_text(value)", "payload[key] = value")],
    "log_level_unchecked": [(LOG, "if level not in LEVELS:", "if False:")],
    "log_handlers_stack_up": [(LOG, "logger.removeHandler(handler)", "pass")],
    "log_propagates": [(LOG, "logger.propagate = False", "logger.propagate = True")],
    # ---- observation schemas -------------------------------------------------------------------
    "schema_unknown_fields_allowed": [(SCH, 'extra="forbid"', 'extra="ignore"')],
    "schema_coercion_allowed": [(SCH, "strict=True,", "strict=False,")],
    "schema_port_floor_lowered": [(SCH, "Field(ge=1, le=65535)", "Field(ge=0, le=65535)")],
    "schema_port_ceiling_raised": [(SCH, "Field(ge=1, le=65535)", "Field(ge=1, le=65536)")],
    "schema_noncanonical_host_accepted": [(SCH, "if host != value:", "if False:")],
    "schema_sha_pattern_weakened": [(SCH, 'Field(pattern=r"^[0-9a-f]{64}$")', 'Field(pattern=r"^[0-9a-fA-F]{64}")')],
    "schema_dns_record_cap_raised": [(SCH, "len(entries) > 32", "len(entries) > 33")],
    "schema_dns_record_length_raised": [(SCH, "len(e) > 255", "len(e) > 256")],
    "schema_header_count_raised": [(SCH, "if len(value) > 64:", "if len(value) > 65:")],
    "schema_header_name_pattern_weakened": [(SCH, 'r"[a-z0-9_-]{1,64}"', 'r"[A-Za-z0-9_ -]{1,64}"')],
    "schema_header_value_length_raised": [(SCH, "any(len(v) > 4096 for v in values)", "any(len(v) > 4097 for v in values)")],
    "schema_header_value_count_raised": [(SCH, "len(values) > 64 or", "len(values) > 65 or")],
    "schema_parsed_depth_raised": [(SCH, "depth > MAX_PARSED_DEPTH + 1", "depth > MAX_PARSED_DEPTH + 2")],
    "schema_parsed_keys_raised": [(SCH, "len(value) > MAX_PARSED_KEYS", "len(value) > MAX_PARSED_KEYS + 1")],
    "schema_parsed_bytes_raised": [(SCH, "> MAX_PARSED_BYTES", "> MAX_PARSED_BYTES * 2")],
    "schema_parsed_lists_not_walked": [(SCH, "elif isinstance(value, list):\n        for item in value:\n            _bounded_json(item, depth + 1)", "elif False:\n        pass")],
    "schema_body_size_raised": [(SCH, "size_bytes: Annotated[int, Field(ge=0, le=2_000_000)]", "size_bytes: Annotated[int, Field(ge=0, le=2_000_001)]")],
    "schema_negative_body_size_allowed": [(SCH, "size_bytes: Annotated[int, Field(ge=0,", "size_bytes: Annotated[int, Field(ge=-1,")],
    "schema_http_status_floor_lowered": [(SCH, "Field(ge=100, le=599)", "Field(ge=99, le=599)")],
    "schema_http_status_ceiling_raised": [(SCH, "Field(ge=100, le=599)", "Field(ge=100, le=600)")],
    "schema_redirect_length_raised": [(SCH, "Field(max_length=2048)", "Field(max_length=2049)")],
    "schema_san_cap_raised": [(SCH, "Field(max_length=100)]", "Field(max_length=101)]")],
    "schema_adapter_type_pairing_unchecked": [(SCH, "if _ADAPTER_FOR[self.observation_type] != self.adapter:", "if False:")],
    "schema_payload_type_unchecked": [(SCH, "if not isinstance(self.payload, _PAYLOADS[self.observation_type]):", "if False:")],
    # a dict payload is shaped by its type first and the isinstance check refuses it again (two layers): remove both
    "schema_payload_shape_unchecked": [(SCH, "if model is not None:", "if False:"), (SCH, "if not isinstance(self.payload, _PAYLOADS[self.observation_type]):", "if False:")],
    "schema_methods_widened": [(SCH, 'method: Literal["GET", "HEAD"]', 'method: Literal["GET", "HEAD", "POST"]')],
    "schema_path_not_canonical": [(SCH, "return canonical_path(value)", "return value")],
    "schema_draft_title_floor_lowered": [(SCH, "Field(min_length=5, max_length=160)", "Field(min_length=4, max_length=160)")],
    "schema_draft_title_ceiling_raised": [(SCH, "Field(min_length=5, max_length=160)", "Field(min_length=5, max_length=161)")],
    "schema_draft_category_unchecked": [(SCH, "if not _CATEGORY.fullmatch(value):", "if False:")],
    "schema_draft_confidence_ceiling_raised": [(SCH, "Field(ge=0.0, le=1.0)", "Field(ge=0.0, le=1.5)")],
    "schema_draft_confidence_floor_lowered": [(SCH, "Field(ge=0.0, le=1.0)", "Field(ge=-0.5, le=1.0)")],
    # ---- the database --------------------------------------------------------------------------
    "db_group_access_allowed": [(DBS, "if stat.S_IMODE(info.st_mode) & 0o077:", "if stat.S_IMODE(info.st_mode) & 0o007:")],
    "db_other_access_allowed": [(DBS, "if stat.S_IMODE(info.st_mode) & 0o077:", "if stat.S_IMODE(info.st_mode) & 0o070:")],
    "db_foreign_owner_allowed": [(DBS, "if info.st_uid != os.getuid():", "if False:")],
    "db_wrong_kind_allowed": [(DBS, "if not wanted(info.st_mode):", "if False:")],
    "db_directory_not_chmodded": [(DBS, "os.chmod(root, 0o700)  # the process umask must not decide this", "pass")],
    "db_file_not_chmodded": [(DBS, "os.chmod(path, 0o600)\n    check_private(path", "pass\n    check_private(path")],
    # the open mode and the chmod after it both keep the file private (two layers): widen the first and remove the second
    "db_file_created_world_readable": [(DBS, "os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)", "os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)"), (DBS, "os.chmod(path, 0o600)\n    check_private(path", "pass\n    check_private(path")],
    "db_unknown_revision_accepted": [(DBS, "if _read_revision(data_dir.db_path) != HEAD_REVISION:", "if False:")],
    "db_missing_database_created": [(DBS, 'if not data_dir.db_path.exists() and not data_dir.db_path.is_symlink():\n        raise StoreError(ErrorCode.STORE_001, f"no database at {data_dir.db_path}', 'if False:\n        raise StoreError(ErrorCode.STORE_001, f"no database at {data_dir.db_path}')],
    "db_foreign_keys_off": [(DBS, 'cursor.execute("PRAGMA foreign_keys = ON")', 'cursor.execute("PRAGMA foreign_keys = OFF")')],
    "db_transactions_deferred": [(DBS, 'connection.exec_driver_sql("BEGIN IMMEDIATE")', 'connection.exec_driver_sql("BEGIN")')],
    "db_busy_timeout_ignored": [(DBS, 'connect_args={"timeout": busy_timeout_ms / 1000}', 'connect_args={"timeout": 5}')],
    "db_failed_block_commits": [(DBS, "        except BaseException:\n            session.rollback()\n            raise", "        except BaseException:\n            session.commit()\n            raise")],
    "db_upgrade_skips_the_permission_check": [(DBS, '    check_private(path, kind="database file")\n    command.upgrade', "    command.upgrade")],
    "db_models_naive_datetimes_accepted": [(MOD, "if value.tzinfo is None:", "if False:")],
    "db_models_timestamp_format_changed": [(MOD, 'STAMP = "%Y-%m-%dT%H:%M:%S.%fZ"', 'STAMP = "%Y-%m-%dT%H:%M:%SZ"')],
    "db_migration_budget_backstop_removed": [(MIG, 'sa.CheckConstraint("budget_spent <= total_budget", name="ck_runs_budget_within_total"),', "")],
    "db_migration_redaction_check_removed": [(MIG, "sa.CheckConstraint(\"redaction_status IN ('redacted', 'metadata_only')\", name=\"ck_artifacts_redaction\"),", "")],
    "db_migration_redaction_check_widened": [(MIG, "redaction_status IN ('redacted', 'metadata_only')", "redaction_status IN ('redacted', 'metadata_only', 'raw')")],
    "db_migration_artifact_size_unbounded": [(MIG, 'sa.CheckConstraint("size BETWEEN 0 AND 2000000", name="ck_artifacts_size"),', "")],
    "db_migration_state_check_removed": [(MIG, 'sa.CheckConstraint(f"state IN ({RUN_STATES})", name="ck_runs_state"),', "")],
    "db_migration_finding_status_check_removed": [(MIG, 'sa.CheckConstraint(f"status IN ({FINDING_STATUSES})", name="ck_finding_drafts_status"),', "")],
    "db_migration_confidence_check_removed": [(MIG, 'sa.CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_finding_drafts_confidence"),', "")],
    "db_migration_audit_actor_check_removed": [(MIG, "sa.CheckConstraint(\"actor_type IN ('human', 'worker', 'model')\", name=\"ck_audit_events_actor_type\"),", "")],
    "db_migration_audit_update_allowed": [(MIG, '"CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events "', '"CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events WHEN 0 "')],
    "db_migration_audit_delete_allowed": [(MIG, '"CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events "', '"CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events WHEN 0 "')],
    "db_migration_foreign_target_allowed": [(MIG, "IS NOT (SELECT engagement_id FROM targets", "IS (SELECT engagement_id FROM targets")],
    "db_migration_idempotency_key_dropped": [(MIG, '"run_id", "adapter", "target_id", "normalized_input_hash", name="uq_observations_idempotency"', '"id", "run_id", name="uq_observations_idempotency"')],
    "db_migration_artifact_unique_global": [(MIG, 'sa.UniqueConstraint("run_id", "sha256", name="uq_artifacts_run_sha256"),', 'sa.UniqueConstraint("sha256", name="uq_artifacts_run_sha256"),')],
    "db_migration_evidence_run_link_dropped": [(MIG, '["observation_id", "run_id"], ["observations.id", "observations.run_id"], name="fk_evidence_observation_run"', '["observation_id"], ["observations.id"], name="fk_evidence_observation_run"')],
    "db_migration_target_endpoint_unique_dropped": [(MIG, 'sa.UniqueConstraint("engagement_id", "host_canonical", "scheme", "port", name="uq_targets_endpoint"),', "")],
    # ---- the audit chain -----------------------------------------------------------------------
    "audit_genesis_changed": [(AUD, 'GENESIS_HASH = "0" * 64', 'GENESIS_HASH = "1" * 64')],
    "audit_chain_crosses_runs": [(AUD, "select(AuditEvent.entry_hash).where(AuditEvent.run_id.is_(run_id))", "select(AuditEvent.entry_hash)")],
    "audit_prev_link_unchecked": [(AUD, "if event.prev_hash != expected_prev:", "if False:")],
    "audit_content_hash_unchecked": [(AUD, "if recomputed != event.entry_hash:", "if False:")],
    "audit_hash_ignores_reason": [(AUD, '"reason": reason,', "")],
    "audit_hash_ignores_decision": [(AUD, '"decision": decision,', "")],
    "audit_hash_ignores_actor": [(AUD, '"actor_id": actor_id,', "")],
    "audit_hash_ignores_actor_type": [(AUD, '"actor_type": actor_type,', "")],
    "audit_hash_ignores_action": [(AUD, '"action": action,', "")],
    "audit_hash_ignores_time": [(AUD, '"ts": ts.astimezone(UTC).strftime(STAMP),', "")],
    "audit_hash_ignores_the_link": [(AUD, '"prev_hash": prev_hash,', "")],
    "audit_hash_ignores_the_run": [(AUD, '"run_id": run_id,', "")],
    "audit_hash_ignores_the_id": [(AUD, '"id": id,', "")],
    "audit_ids_skip": [(AUD, "or 0) + 1", "or 0) + 2")],
    "audit_decision_unchecked": [(AUD, "if decision not in _DECISIONS:", "if False:")],
    "audit_blank_action_allowed": [(AUD, "if not action.strip():", "if False:")],
    "audit_naive_time_allowed": [(AUD, "if now.tzinfo is None:", "if False:")],
    "audit_reason_not_cleaned": [(AUD, "cleaned_reason = safe_text(reason, 500)", "cleaned_reason = reason")],
    "audit_reason_unbounded": [(AUD, "cleaned_reason = safe_text(reason, 500)", "cleaned_reason = safe_text(reason, 50000)")],
    "audit_verify_stops_early": [(AUD, "expected_prev = event.entry_hash", "expected_prev = GENESIS_HASH if count == 0 else event.entry_hash")],
    # ---- the budget ----------------------------------------------------------------------------
    "budget_off_by_one": [(BUD, "budget_spent + :units <= total_budget", "budget_spent + :units < total_budget")],
    "budget_over_by_one": [(BUD, "budget_spent + :units <= total_budget", "budget_spent + :units <= total_budget + 1")],
    "budget_any_state": [(BUD, "AND state = 'COLLECTING' ", "")],
    "budget_release_unguarded": [(BUD, "WHERE id = :run AND budget_spent >= :units", "WHERE id = :run")],
    "budget_permit_returned_twice": [(BUD, 'if permit._returned:', 'if False:')],
    "budget_permit_never_marked": [(BUD, 'permit._returned = True', 'pass')],
    "budget_units_unbounded": [(BUD, "or not 1 <= units <= MAX_UNITS:", "or not 1 <= units:")],
    "budget_zero_units_allowed": [(BUD, "or not 1 <= units <= MAX_UNITS:", "or not 0 <= units <= MAX_UNITS:")],
    "budget_bool_units_allowed": [(BUD, "isinstance(units, bool) or", "False or")],
    "budget_max_units_raised": [(BUD, "MAX_UNITS = 500", "MAX_UNITS = 501")],
    "budget_denial_not_kept": [(BUD, "session.commit()  # keep the denial", "pass  # keep the denial")],
    "budget_exhaustion_is_silent": [(BUD, "raise BudgetError(ErrorCode.BUDGET_001", "return Permit(run_id=run_id, units=0)  # raise BudgetError(ErrorCode.BUDGET_001")],
    # ---- repositories: engagements and runs ----------------------------------------------------
    "register_expired_scope_allowed": [(REP, "    check_not_expired(loaded.config.expires_at, now)\n    existing", "    existing")],
    "register_never_reuses": [(REP, "if existing is not None:\n        return existing", "if False:\n        return existing")],
    "register_targets_unverified": [(REP, "verified_scope=True", "verified_scope=False")],
    "register_drops_paths": [(REP, "allowed_path_prefixes=list(entry.allowed_paths)", "allowed_path_prefixes=[]")],
    "register_stores_unnormalised_scope": [(REP, "scope_json=loaded.canonical_json", 'scope_json="{}"')],
    "create_run_by_anyone": [(REP, 'if actor.type is not ActorType.HUMAN:', 'if False:')],
    "create_run_expiry_ignored": [(REP, "    check_not_expired(engagement.expires_at, now)\n    scope", "    scope")],
    "create_run_live_allowed": [(REP, 'if scope["mode"] != "offline":', "if False:")],
    "create_run_budget_not_from_scope": [(REP, 'total_budget=scope["max_requests"]', "total_budget=1")],
    "create_run_unaudited": [(REP, '        decision="allowed",\n        reason=f"engagement {engagement.label}",', '        decision="recorded",\n        reason=f"engagement {engagement.label}",')],
    "transition_expected_state_ignored": [(REP, "if expected is not None and expected is not src:", "if False:")],
    "transition_unconditional_update": [(REP, "update(Run).where(Run.id == run_id, Run.state == src.value)", "update(Run).where(Run.id == run_id)")],
    "transition_started_at_never_set": [(REP, "if dst is RunState.COLLECTING:\n        values[\"started_at\"] = now", "if False:\n        values[\"started_at\"] = now")],
    "transition_ended_at_never_set": [(REP, "if dst in TERMINAL_RUN_STATES and run.ended_at is None:", "if False:")],
    "transition_ended_at_overwritten": [(REP, "if dst in TERMINAL_RUN_STATES and run.ended_at is None:", "if dst in TERMINAL_RUN_STATES:")],
    "transition_error_code_dropped": [(REP, "if error_code is not None:\n        values[\"error_code\"] = error_code", "if False:\n        values[\"error_code\"] = error_code")],
    "transition_denial_not_kept": [(REP, '    append_event(session, run_id=run_id, actor=actor, action=action, decision="denied", reason=reason, now=now)\n    session.commit()', '    append_event(session, run_id=run_id, actor=actor, action=action, decision="denied", reason=reason, now=now)')],
    "transition_actor_check_skipped": [(REP, "        check_run_transition(src, dst, actor)\n    except StateError as exc:", "        pass\n    except StateError as exc:")],
    "retry_attempt_not_incremented": [(REP, "attempt = old.attempt + 1", "attempt = old.attempt")],
    "retry_forgets_its_parent": [(REP, "retry_of_run_id=old.id,", "")],
    "retry_keeps_the_spend": [(REP, '        budget_spent=0,\n        attempt=attempt,', '        budget_spent=old.budget_spent,\n        attempt=attempt,')],
    "retry_forgets_the_budget": [(REP, '        total_budget=old.total_budget,\n', '        total_budget=1,\n')],
    "retry_does_not_close_the_old_run": [(REP, "transition_run(session, run_id, RunState.RETRIED,", "(lambda *a, **k: None)(session, run_id, RunState.RETRIED,")],
    "list_limit_unchecked": [(REP, "if not 1 <= limit <= MAX_PAGE:", "if False:")],
    "list_page_ceiling_raised": [(REP, "MAX_PAGE = 100", "MAX_PAGE = 101")],
    "list_offset_unchecked": [(REP, "if offset < 0:", "if False:")],
    "list_oldest_first": [(REP, "Run.created_at.desc(), Run.id.desc()", "Run.created_at.asc(), Run.id.asc()")],
    # ---- repositories: observations and findings -----------------------------------------------
    "observation_source_hash_unchecked": [(REP, "if not _SHA256.fullmatch(source_hash):", "if False:")],
    "observation_naive_time_allowed": [(REP, "if collected_at.tzinfo is None:", "if False:")],
    "observation_by_anyone": [(REP, 'if actor.type is not ActorType.WORKER:', 'if False:')],
    "observation_in_any_state": [(REP, 'if run.state != RunState.COLLECTING.value:', 'if False:')],
    # the application checks the engagement and the database trigger checks it again: remove the application check, keep the trigger, and the error type changes
    "observation_target_unchecked": [(REP, '        or target.engagement_id != run.engagement_id\n        or (target.host_canonical, target.scheme, target.port) != wanted\n', '')],
    "observation_envelope_target_unchecked": [(REP, '        or (target.host_canonical, target.scheme, target.port) != wanted\n', '')],
    "observation_replay_overwrites": [(REP, "if existing is not None:\n        append_event(", "if False:\n        append_event(")],
    "observation_replay_reports_created": [(REP, "return existing, False", "return existing, True")],
    "observation_error_status_dropped": [(REP, "error_status=envelope.error_status.value,", 'error_status="ok",')],
    "observation_json_unsorted": [(REP, "json.dumps(envelope.payload.model_dump(mode=\"json\"), sort_keys=True,", "json.dumps(envelope.payload.model_dump(mode=\"json\"), sort_keys=False,")],
    "observation_input_hash_not_of_the_input": [(REP, "hashlib.sha256(envelope.normalized_input.encode()).hexdigest()", "hashlib.sha256(envelope.observation_type.encode()).hexdigest()")],
    "observation_unaudited": [(REP, '        action="observation.recorded",\n        decision="allowed",', '        action="observation.recorded",\n        decision="recorded",')],
    "draft_by_the_model": [(REP, 'if actor.type is ActorType.MODEL:', 'if False:')],
    "draft_in_any_state": [(REP, "if run.state != RunState.CORRELATING.value:", "if False:")],
    "draft_without_evidence": [(REP, "if not ids or len(set(ids)) != len(ids) or found != len(ids):", "if len(set(ids)) != len(ids) or found != len(ids):")],
    # (no mutant for repeated evidence ids: the duplicate check and the count check both refuse it, so removing one is equivalent)
    "draft_with_foreign_evidence": [(REP, "Observation.run_id == run_id, Observation.id.in_(ids)", "Observation.id.in_(ids)")],
    "draft_with_missing_evidence": [(REP, "or found != len(ids):", ":")],
    "draft_starts_validated": [(REP, '        status=FindingStatus.DRAFT.value,\n        reviewer_id=None,', '        status=FindingStatus.VALIDATED.value,\n        reviewer_id=None,')],
    "draft_starts_at_revision_zero": [(REP, '        reviewer_id=None,\n        revision=1,', '        reviewer_id=None,\n        revision=2,')],
    "finding_stale_revision_ignored": [(REP, "if expected_revision is not None and expected_revision != finding.revision:", "if False:")],
    "finding_revision_not_bumped": [(REP, '"revision": finding.revision + 1', '"revision": finding.revision')],
    "finding_workers_become_reviewers": [(REP, "if dst is not FindingStatus.NEEDS_VALIDATION:\n        values[\"reviewer_id\"] = actor.id", "if True:\n        values[\"reviewer_id\"] = actor.id")],
    "finding_reviewer_never_recorded": [(REP, 'values["reviewer_id"] = actor.id', "pass")],
    "finding_evidence_not_counted": [(REP, 'select(func.count()).select_from(FindingEvidence).where(FindingEvidence.finding_id == finding_id)', 'select(func.count()).select_from(FindingEvidence).where(FindingEvidence.finding_id == finding_id).where(FindingEvidence.finding_id != finding_id)')],
    "finding_actor_check_skipped": [(REP, "        check_finding_transition(src, dst, actor=actor, reason=reason, evidence_count=evidence)\n    except StateError as exc:", "        pass\n    except StateError as exc:")],
    "finding_unconditional_update": [(REP, "FindingDraft.id == finding_id, FindingDraft.revision == finding.revision", "FindingDraft.id == finding_id")],
    # ---- artifacts -----------------------------------------------------------------------------
    "artifact_non_bytes_accepted": [(ART, "if not isinstance(content, bytes):", "if False:")],
    "artifact_empty_accepted": [(ART, "if not content:", "if False:")],
    "artifact_size_cap_exclusive": [(ART, "if len(content) > MAX_ARTIFACT_BYTES:", "if len(content) >= MAX_ARTIFACT_BYTES:")],
    "artifact_size_cap_raised": [(ART, "MAX_ARTIFACT_BYTES = 2_000_000", "MAX_ARTIFACT_BYTES = 2_000_001")],
    "artifact_raw_content_accepted": [(ART, "if redaction_status not in _REDACTION:", "if False:")],
    "artifact_raw_status_listed": [(ART, '_REDACTION = ("redacted", "metadata_only")', '_REDACTION = ("redacted", "metadata_only", "raw")')],
    "artifact_mime_unchecked": [(ART, "if not isinstance(mime, str) or not _MIME.fullmatch(mime):", "if False:")],
    "artifact_retention_floor_lowered": [(ART, "MIN_RETENTION_DAYS = 1", "MIN_RETENTION_DAYS = 0")],
    "artifact_retention_ceiling_raised": [(ART, "MAX_RETENTION_DAYS = 365", "MAX_RETENTION_DAYS = 366")],
    "artifact_retention_unchecked": [(ART, "if not MIN_RETENTION_DAYS <= retention_days <= MAX_RETENTION_DAYS:", "if False:")],
    "artifact_default_retention_longer": [(ART, "DEFAULT_RETENTION_DAYS = 30", "DEFAULT_RETENTION_DAYS = 31")],
    "artifact_stored_by_anyone": [(ART, 'if actor.type is not ActorType.WORKER:', 'if False:')],
    "artifact_path_not_a_digest": [(ART, "if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):", "if False:")],
    "artifact_digest_pattern_weakened": [(ART, '_SHA256 = re.compile(r"[0-9a-f]{64}")', '_SHA256 = re.compile(r"[0-9a-fA-F/.]{1,200}")')],
    "artifact_directory_not_private": [(ART, "path.mkdir(mode=0o700)\n        os.chmod(path, 0o700)", "path.mkdir(mode=0o777)")],
    "artifact_directory_perms_unchecked": [(ART, '            check_private(path, kind="data directory")\n            return', "            return")],
    "artifact_link_directories_followed": [(ART, "if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):", "if False:")],
    "artifact_file_not_private": [(ART, "os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)", "os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)")],
    "artifact_links_followed": [(ART, "if not stat.S_ISREG(info.st_mode):\n            raise StoreError(ErrorCode.STORE_004, \"an artifact path is a link", "if False:\n            raise StoreError(ErrorCode.STORE_004, \"an artifact path is a link")],
    "artifact_duplicate_not_verified": [(ART, "self._verify_file(path, sha256)  # a duplicate", "pass  # a duplicate")],
    "artifact_hash_not_checked_on_read": [(ART, "or hashlib.sha256(content).hexdigest() != sha256:", "or False:")],
    # (no mutant for reading a stored file unbounded: the size check still runs on what was read, so only memory use changes)
    "artifact_write_not_atomic": [(ART, "os.replace(temporary, path)", "path.write_bytes(content)")],
    # fsync and the directory sync are two layers of the same durability promise: remove both
    "artifact_write_not_synced": [(ART, "os.fsync(descriptor)", "pass"), (ART, "os.fsync(directory)", "pass")],
    "artifact_orphan_kept_after_db_failure": [(ART, "if created_file:  # never leave an orphan that no row accounts for\n                path.unlink(missing_ok=True)", "if False:\n                pass")],
    "artifact_shared_file_removed_after_db_failure": [(ART, "if created_file:  # never leave an orphan", "if True:  # never leave an orphan")],
    "artifact_duplicate_row_per_run": [(ART, "if existing is not None:\n                return existing", "if False:\n                return existing")],
    "artifact_run_scope_ignored": [(ART, "Artifact.run_id == run_id, Artifact.sha256 == sha256", "Artifact.sha256 == sha256")],
    "artifact_unaudited": [(ART, '                action="artifact.stored",\n                decision="allowed",', '                action="artifact.stored",\n                decision="recorded",')],
    "purge_by_anyone": [(ART, 'if actor.type is not ActorType.HUMAN:', 'if False:')],
    "purge_cut_off_inclusive": [(ART, "Artifact.retention_until < before", "Artifact.retention_until <= before")],
    "purge_naive_cut_off_allowed": [(ART, "if before.tzinfo is None:", "if False:")],
    "purge_forged_path_trusted": [(ART, 'if row.storage_path != f"{row.sha256[:2]}/{row.sha256}":', "if False:")],
    "purge_deletes_shared_files": [(ART, "Artifact.sha256 == sha, Artifact.id.not_in(due_ids)", "Artifact.sha256 == sha, Artifact.id.in_(due_ids)")],
    "purge_follows_links": [(ART, "if not stat.S_ISREG(info.st_mode):\n            raise StoreError(ErrorCode.STORE_004, \"an artifact path is a link", "if False:\n            raise StoreError(ErrorCode.STORE_004, \"an artifact path is a link")],
    "purge_keeps_the_rows": [(ART, "session.execute(delete(Artifact).where(Artifact.id.in_(due_ids)))", "pass")],
    "purge_without_receipt": [(ART, '            action="artifacts.purge",\n            decision="allowed",', '            action="artifacts.purge",\n            decision="recorded",')],
    "purge_miscounts_files": [(ART, "files_deleted += 1", "files_deleted += 2")],
    # ---- the command line ----------------------------------------------------------------------
    "cli_errors_always_exit_one": [(CLI, "return typer.Exit(error.exit_code)", "return typer.Exit(1)")],
    "cli_errors_always_exit_two": [(CLI, "return typer.Exit(error.exit_code)", "return typer.Exit(2)")],
    "cli_default_data_dir_fixed_at_import": [(CLI, "return DataDir(chosen if chosen is not None else default_data_dir())", "return DataDir(chosen if chosen is not None else Path('/nonexistent-scopedagent'))")],
    "cli_xdg_ignored": [(CLI, 'base = os.environ.get("XDG_DATA_HOME")', "base = None")],
    "cli_page_limit_unchecked": [(CLI, "if not 1 <= limit <= MAX_PAGE or offset < 0:", "if False:")],
    "cli_negative_offset_allowed": [(CLI, "if not 1 <= limit <= MAX_PAGE or offset < 0:", "if not 1 <= limit <= MAX_PAGE:")],
    "cli_warning_on_equal_budget": [(CLI, "if len(loaded.planned) > config.max_requests:", "if len(loaded.planned) >= config.max_requests:")],
    "cli_warning_never": [(CLI, "if len(loaded.planned) > config.max_requests:", "if False:")],
    "cli_no_authorization_notice": [(CLI, 'typer.echo(f"note: {AUTHORIZATION_NOTICE}")', "pass")],
    "cli_hash_not_shown": [(CLI, 'typer.echo(f"scope sha256: {loaded.sha256}")', "pass")],
    "cli_counts_wrong": [(CLI, "http {counts['http_metadata']})", "http {counts['dns_metadata']})")],
    "cli_expiry_not_utc": [(CLI, 'moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")', 'moment.strftime("%Y-%m-%dT%H:%M:%SZ")')],
    "cli_validate_uses_wall_clock": [(CLI, "now=_context(ctx).clock()", "now=_now()")],
    "cli_unknown_run_verifies": [(CLI, "if session.get(Run, run_id) is None:", "if False:")],
    "cli_verify_hides_a_broken_chain": [(CLI, "count = verify_chain(session, run_id)", "count = 0")],
    "cli_runs_not_newest_first": [(CLI, "runs = list_runs(session, limit=limit, offset=offset)", "runs = list(reversed(list_runs(session, limit=limit, offset=offset)))")],
    "cli_empty_history_is_silent": [(CLI, 'typer.echo("no runs")', "pass")],
    "cli_db_upgrade_reports_nothing": [(CLI, 'typer.echo(f"database ready: revision {revision}', 'typer.echo(f"revision {revision}')],
}  # fmt: skip

IGNORE = shutil.ignore_patterns(
    ".venv",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "out",
    ".scopedagent",
    ".coverage",
)
TEST_PATHS = ["tests/unit", "tests/negative", "tests/integration", "tests/adversarial", "tests/property"]


def run_one(work: Path, edits: list[tuple[str, str, str]]) -> tuple[str, str]:
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(REPO, work, ignore=IGNORE)
    for relative, old, new in edits:
        path = work / relative
        text = path.read_text(encoding="utf-8")
        if old not in text:
            return "NOAPPLY", f"pattern not found in {relative}: {old[:70]!r}"
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=f"{work / 'src'}:{work}")
    imported = subprocess.run(
        [sys.executable, "-c", "import scopedagent; print(scopedagent.__file__)"],
        capture_output=True, text=True, env=env, cwd=work, check=False,
    ).stdout.strip()  # fmt: skip
    if not imported.startswith(str(work)):
        return "NOAPPLY", f"the scratch copy is not the imported package: {imported}"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *TEST_PATHS, "-q", "--tb=no", "-x", "-p", "no:cacheprovider", "--no-header"],
        cwd=work, env=env, capture_output=True, text=True, timeout=600, check=False,
    )  # fmt: skip
    tail = (result.stdout.strip().splitlines() or [result.stderr[-200:]])[-1]
    return ("KILLED" if result.returncode != 0 else "SURVIVED"), tail


def main(names: list[str]) -> int:
    chosen = {n: M[n] for n in names} if names else M
    unknown = [n for n in names if n not in M]
    if unknown:
        print(f"unknown mutant(s): {unknown}")
        return 2
    counts = {"KILLED": 0, "SURVIVED": 0, "NOAPPLY": 0}
    with tempfile.TemporaryDirectory(prefix="scopedagent-mutation-") as scratch:
        verdict, info = run_one(Path(scratch) / "work", [])
        if verdict != "SURVIVED":  # "SURVIVED" with no edits means nothing failed: the baseline is green
            print(f"BASELINE NOT GREEN ({verdict}): {info}\nrefusing to run mutants")
            return 2
        print(f"baseline green | {info}", flush=True)
        for name, edits in chosen.items():
            try:
                verdict, info = run_one(Path(scratch) / "work", edits)
            except subprocess.TimeoutExpired:
                verdict, info = "KILLED", "timed out (a hang is a failure)"
            counts[verdict] += 1
            print(f"{verdict:9} {name} | {info}", flush=True)
    print(
        f"\nTOTAL {len(chosen)}  killed {counts['KILLED']}  survived {counts['SURVIVED']}  noapply {counts['NOAPPLY']}"
    )
    if counts["NOAPPLY"]:
        return 2
    return 1 if counts["SURVIVED"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
