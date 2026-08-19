-- 30_defenses.sql — install two out-of-engine-style, pure-SQL detective/preventive
-- controls that DON'T depend on the app role behaving, and expose the attacks:
--   (D-ET) an event trigger that fires on ddl_command_end and records any DDL that
--          touches audit-schema objects (catches 1C / Exp2 function replacement).
--   (D-HC) a hash-chained, append-only mirror of the audit stream so that a
--          fabricated/backdated row (Exp3) inserted directly into audit.logged_actions
--          breaks chain verification.
-- (The knob-based defenses — REVOKE CREATE ON public, pinned search_path, correct
--  ownership — are exercised by re-running attacks with hardened knobs in run_matrix.sh.)
\set ON_ERROR_STOP on
\c labdb

-- ============================ D-ET: DDL event-trigger guard ============================
CREATE TABLE IF NOT EXISTS audit.ddl_watch (
  id        bigserial PRIMARY KEY,
  seen_at   timestamptz NOT NULL DEFAULT now(),
  who       text NOT NULL DEFAULT session_user,
  command   text,
  objid     text
);

-- SECURITY DEFINER helper so the log write succeeds no matter which (low-priv) role
-- triggered the DDL — event-trigger functions otherwise run AS the triggering role.
CREATE OR REPLACE FUNCTION audit.ddl_record(p_cmd text, p_obj text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  INSERT INTO audit.ddl_watch(command, objid) VALUES (p_cmd, p_obj);
END; $$;
-- EXECUTE stays with PUBLIC: the triggering role must be able to CALL the helper;
-- the DEFINER context is what elevates the INSERT into audit.ddl_watch.

CREATE OR REPLACE FUNCTION audit.on_ddl() RETURNS event_trigger
LANGUAGE plpgsql AS $$
DECLARE r record;
BEGIN
  FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
    IF r.schema_name = 'audit' OR r.object_identity LIKE 'audit.%' THEN
      PERFORM audit.ddl_record(r.command_tag, r.object_identity);   -- via DEFINER helper
    END IF;
  END LOOP;
END; $$;

DROP EVENT TRIGGER IF EXISTS audit_ddl_guard;
CREATE EVENT TRIGGER audit_ddl_guard ON ddl_command_end EXECUTE FUNCTION audit.on_ddl();
-- Event triggers are cluster/DB-level objects owned by the DBA; app_role cannot DROP them.

-- ============================ D-HC: hash-chained append-only sink ============================
CREATE TABLE IF NOT EXISTS audit.secure_log (
  seq       bigserial PRIMARY KEY,
  payload   jsonb NOT NULL,
  prev_hash text NOT NULL,
  this_hash text NOT NULL
);

-- append one record, chaining it to the prior hash (genesis = 64 zeros)
CREATE OR REPLACE FUNCTION audit.secure_append(p jsonb) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE ph text; nh text;
BEGIN
  SELECT this_hash INTO ph FROM audit.secure_log ORDER BY seq DESC LIMIT 1;
  ph := COALESCE(ph, repeat('0',64));
  nh := encode(digest(ph || p::text, 'sha256'), 'hex');
  INSERT INTO audit.secure_log(payload, prev_hash, this_hash) VALUES (p, ph, nh);
END; $$;

-- verify the whole chain; returns the first broken seq, or NULL if intact
CREATE OR REPLACE FUNCTION audit.secure_verify() RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE r record; ph text := repeat('0',64); calc text;
BEGIN
  FOR r IN SELECT * FROM audit.secure_log ORDER BY seq LOOP
    calc := encode(digest(ph || r.payload::text, 'sha256'), 'hex');
    IF calc <> r.this_hash OR r.prev_hash <> ph THEN
      RETURN r.seq;                              -- tamper detected here
    END IF;
    ph := r.this_hash;
  END LOOP;
  RETURN NULL;                                   -- intact
END; $$;

-- pgcrypto provides digest(); enable it (DBA-only)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

SELECT 'DEFENSES_INSTALLED' AS tag;
