# Migrations

The schema is managed by Alembic and changed only by `scoped-agent db upgrade` (D-E10). The tool never migrates on startup: a
database at a revision this version does not know is refused (`STORE-002`) with the command to run.

* Revision `0001` is explicit DDL, not generated from the models, so changing a model can never rewrite what 0001 means.
  `tests/integration/test_database.py` compares the migrated database with the models: tables, columns, unique constraints,
  foreign keys, every CHECK constraint, and the triggers.
* Revision `0002` (M3, D-E62) adds `runs.planned_operations` (NULL for a run made before it), the immutable `finding_details`
  table and the append-only `finding_reviews` table, each with a no-update and a no-delete trigger. A database at `0001` is
  refused with the command to run, and `db upgrade` brings it forward and keeps its data (tested).
* Revision `0003` (M4, D-E69) adds the append-only `model_calls` and `finding_wordings` tables, each with a no-update and a no-delete
  trigger. It changes no existing table, so a database at `0002` keeps its data (tested). A database at `0002` is refused with the
  command to run until `db upgrade`.
* Revision `0004` (M5, D-E70) admits the API target and observation kinds. SQLite cannot alter a CHECK constraint, so `targets` and
  `observations` are **rebuilt**: the new table is created with the wider lists, every row is copied unchanged, the old table is
  dropped and the new one takes its name, and the trigger that keeps an observation inside its run's engagement is recreated. It is
  one transaction (a failure anywhere leaves revision `0003` exactly as it was) and it stops, undoing everything, if a row was lost or
  a row refers to a row that is not there. Before it runs, `db upgrade` copies the database file aside (`evidence.sqlite.before-0003`,
  then `.1`, `.2`, ... so an older copy is never replaced; mode `0600`) and prints the path. Tests rebuild a database holding the rows
  of two real runs and compare every row and the whole schema before and after. This is the only revision so far that rewrites existing
  records, so it needs the owner's approval before it is merged.
* Triggers: `audit_events_no_update` and `audit_events_no_delete` (the audit trail is append-only) and
  `observations_target_in_engagement` (an observation must belong to a target of the run's own engagement).
* **Forward only.** There is no downgrade: it raises. To go back, restore the database file from a backup made before the upgrade.
  Back up `evidence.sqlite` (and the `artifacts/` directory) before upgrading; SQLite does not roll back a half-applied DDL
  script, and revision 0001 runs against an empty database, so a failure there leaves a file to delete and recreate.
* Adding a revision: write `versions/NNNN_name.py` by hand, set `down_revision`, bump `HEAD_REVISION` in
  `storage/database.py`, change the models, and extend the equivalence tests. Additive changes only where a deployed database
  holds data; anything that rewrites or deletes real records needs the owner's approval first.
