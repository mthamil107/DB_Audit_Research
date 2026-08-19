-- 10_victim.sql  — build the "victim" trigger-based audit system (run as superuser).
-- Parameterized by psql vars so run_matrix.sh can force each Feasibility-Matrix
-- precondition into a KNOWN state regardless of PG version defaults:
--   -v pub_create=on|off   force PUBLIC CREATE on schema public (on = vulnerable precondition)
--   -v pin_path=on|off     pin the trigger function's search_path (on = hardened)
--   -v app_owns=on|off     make app_role own the audit function (on = ownership misconfig)
--
-- Synthetic data only. RFC 5737 doc IPs. Local throwaway DB.
\set ON_ERROR_STOP on

-- default the knobs off if invoked standalone
\if :{?pub_create}
\else
  \set pub_create off
\endif
\if :{?pin_path}
\else
  \set pin_path off
\endif
\if :{?app_owns}
\else
  \set app_owns off
\endif

-- rebuild from scratch (connected to the maintenance DB 'postgres')
\c postgres
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
  WHERE datname = 'labdb' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS labdb;
CREATE DATABASE labdb;

-- role is cluster-wide; recreate cleanly
DROP ROLE IF EXISTS app_role;
CREATE ROLE app_role LOGIN PASSWORD 'app_pw';

\c labdb

-- 3.2 business schema + table (synthetic)
CREATE SCHEMA app AUTHORIZATION app_role;
CREATE TABLE app.accounts (
  id            bigserial PRIMARY KEY,
  holder        text   NOT NULL,
  balance_cents bigint NOT NULL DEFAULT 0
);

-- 3.3 audit schema + store, owned by the DBA (postgres), NOT by app_role
CREATE SCHEMA audit;
CREATE TABLE audit.logged_actions (
  event_id    bigserial   PRIMARY KEY,
  table_name  text        NOT NULL,
  action      text        NOT NULL,           -- I/U/D
  row_data    jsonb,                          -- captured via row_to_json (implicit built-in dep)
  changed_by  text        NOT NULL DEFAULT session_user,
  client_ip   inet        DEFAULT inet_client_addr(),
  logged_at   timestamptz NOT NULL DEFAULT now()
);

-- 3.4 the trigger function — IMPLICIT unqualified built-in dependency (row_to_json)
CREATE OR REPLACE FUNCTION audit.if_modified()
RETURNS trigger AS $$
DECLARE
  payload jsonb;
BEGIN
  IF (TG_OP = 'DELETE') THEN
    payload := row_to_json(OLD)::jsonb;      -- unqualified pg_catalog built-in — design under test
  ELSE
    payload := row_to_json(NEW)::jsonb;
  END IF;
  INSERT INTO audit.logged_actions(table_name, action, row_data)
  VALUES (TG_TABLE_NAME, left(TG_OP,1), payload);
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql
   SECURITY DEFINER;                          -- faithful to the wiki pattern: runs as the
                                              -- fn OWNER so low-priv writers CAN be audited.
                                              -- Default (mutable) search_path unless pinned below.
                                              -- (This DEFINER + unpinned path is the CVE-2018-1058 surface.)

CREATE TRIGGER accounts_audit
  AFTER INSERT OR UPDATE OR DELETE ON app.accounts
  FOR EACH ROW EXECUTE FUNCTION audit.if_modified();

-- 3.5 app grants — the ONLY privileges the attacker holds by default
GRANT USAGE ON SCHEMA app TO app_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.accounts TO app_role;
GRANT USAGE ON SEQUENCE app.accounts_id_seq TO app_role;
-- app_role deliberately has NO privileges on schema audit or its objects.

------------------------------------------------------------------------------
-- Precondition knobs (forced to a known state; normalizes PG14 vs PG16 defaults)
------------------------------------------------------------------------------
\if :pub_create
  GRANT CREATE, USAGE ON SCHEMA public TO PUBLIC;     -- force the vulnerable precondition
\else
  REVOKE CREATE ON SCHEMA public FROM PUBLIC;         -- hardened
\endif

\if :pin_path
  ALTER FUNCTION audit.if_modified() SET search_path = pg_catalog, audit;  -- hardened
\endif

\if :app_owns
  -- Model the "one migration role owns everything" misconfig: app_role owns the
  -- audit fn (so it can CREATE OR REPLACE it) and can write the audit table (so the
  -- DEFINER fn, now running as app_role, can still insert during the baseline).
  ALTER FUNCTION audit.if_modified() OWNER TO app_role;    -- the ownership MISCONFIG
  GRANT USAGE, CREATE ON SCHEMA audit TO app_role;         -- reach + replace the fn
  GRANT INSERT ON audit.logged_actions TO app_role;        -- DEFINER=app_role must insert
  GRANT USAGE ON SEQUENCE audit.logged_actions_event_id_seq TO app_role;
\endif

-- Report the state we actually built (captured into the results file)
SELECT 'VICTIM_STATE'
     , :'pub_create'  AS pub_create
     , :'pin_path'    AS pin_path
     , :'app_owns'    AS app_owns;

SELECT 'PUBLIC_ACL_DEFAULT_CHECK' AS tag,
       has_schema_privilege('app_role','public','CREATE') AS app_can_create_public;

-- Baseline sanity: a write as the DBA should log (proves the pipeline works)
INSERT INTO app.accounts(holder, balance_cents) VALUES ('synthetic-baseline-dba', 1);
SELECT 'BASELINE_AUDIT_COUNT' AS tag, count(*) AS n FROM audit.logged_actions
  WHERE row_data->>'holder' = 'synthetic-baseline-dba';
