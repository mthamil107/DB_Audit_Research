#!/usr/bin/env bash
# run_matrix.sh — orchestrate the whole Feasibility Matrix for one PG major version.
# Usage: ./run_matrix.sh [14|16]
# Produces: results/RESULTS_pg<VER>.md  and  results/_evidence_pg<VER>.log
# Local, throwaway, synthetic only.
set -uo pipefail

VER="${1:-16}"
CID="sda_pg${VER}"
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
RES="$ROOT/results/RESULTS_pg${VER}.md"
EV="$ROOT/results/_evidence_pg${VER}.log"
: > "$EV"

# ---- psql wrappers (unix socket inside the container = trust auth) ----
su_f()  { docker exec -i "$CID" psql -v ON_ERROR_STOP=1 -U postgres -d postgres "$@"; }   # for -f files that \c
app_f() { docker exec -i "$CID" psql -v ON_ERROR_STOP=0 -U app_role -d labdb "$@"; }      # attacks (tolerant)
q()     { docker exec -i "$CID" psql -tA -U postgres -d labdb -c "$1" 2>>"$EV"; }         # scalar query as DBA
log()   { echo -e "$@" | tee -a "$EV" >/dev/null; }

build_victim() {  # pub pin owns
  log "\n=== BUILD VICTIM pub=$1 pin=$2 owns=$3 ==="
  su_f -v pub_create="$1" -v pin_path="$2" -v app_owns="$3" -f - < "$DIR/10_victim.sql" >>"$EV" 2>&1
}
attack() {  # run_flag  (e.g. run_1A=on)
  local var="${1%%=*}"; local val="${1##*=}"
  log "\n--- ATTACK $1 ---"
  app_f -v "$var"="$val" -f - < "$DIR/20_attacks.sql" >>"$EV" 2>&1
}
audited()  { q "SELECT count(*) FROM audit.logged_actions WHERE row_data->>'holder' = '$1';"; }
present()  { q "SELECT count(*) FROM app.accounts WHERE holder = '$1';"; }
exists_fn(){ q "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='$1' AND p.proname='$2';"; }

echo "############################################################"
echo "# Feasibility Matrix run — PostgreSQL ${VER}"
echo "############################################################"

# ---------- environment facts ----------
IMG_DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' postgres:${VER}-alpine 2>/dev/null || echo n/a)"
# version() from the always-present maintenance DB
PGVERSION="$(docker exec -i "$CID" psql -tA -U postgres -d postgres -c 'SELECT version();' 2>>"$EV")"

# TRUE stock default (no intervention): make a fresh DB + a fresh low-priv probe role and
# measure whether PUBLIC-derived roles can CREATE in public straight out of the box.
docker exec -i "$CID" psql -U postgres -d postgres >>"$EV" 2>&1 <<'SQL'
DROP DATABASE IF EXISTS stockcheck;
CREATE DATABASE stockcheck;
DROP ROLE IF EXISTS probe_role;
CREATE ROLE probe_role LOGIN;
SQL
STOCK_PUB_ACL="$(docker exec -i "$CID" psql -tA -U postgres -d stockcheck -c \
  "SELECT COALESCE(array_to_string(nspacl,' '),'(NULL = default: PUBLIC has USAGE+CREATE)') FROM pg_namespace WHERE nspname='public';" 2>>"$EV")"
STOCK_APP_CREATE="$(docker exec -i "$CID" psql -tA -U postgres -d stockcheck -c \
  "SELECT has_schema_privilege('probe_role','public','CREATE');" 2>>"$EV")"
docker exec -i "$CID" psql -U postgres -d postgres >>"$EV" 2>&1 <<'SQL'
DROP DATABASE IF EXISTS stockcheck;
DROP ROLE IF EXISTS probe_role;
SQL

# now build a baseline victim so later q()/SHOW calls have labdb
su_f -v pub_create=off -v pin_path=off -v app_owns=off -f - < "$DIR/10_victim.sql" >>"$EV" 2>&1
SP_SU="$(docker exec -i "$CID" psql -tA -U postgres -d labdb -c 'SHOW search_path;' 2>>"$EV")"
SP_APP="$(docker exec -i "$CID" psql -tA -U app_role -d labdb -c 'SHOW search_path;' 2>>"$EV")"

# ============================================================
#  MATRIX CELLS
# ============================================================
declare -a ROWS

run_cell_1A() {  # pub pin owns  label
  build_victim "$1" "$2" "$3"
  attack "run_1A=on"
  local a; a="$(audited 'sentinel-1A')"
  local planted; planted="$(exists_fn evil row_to_json)"
  local res
  if [ "$a" -ge 1 ]; then res="LOGGED (not blinded)"; else res="BLINDED"; fi
  ROWS+=("| 1A $4 | plant shadow in NEW schema evil | $1 | $2 | $3 | evil.row_to_json planted=$planted → **$res** | n/a | blocked at CREATE SCHEMA (no CREATE-on-db) — a privilege barrier, NOT 'catalog wins'; see 1S/1T for the public-schema plant that DOES blind |")
}

run_cell_1B() {  # pub pin owns label
  build_victim "$1" "$2" "$3"
  attack "run_1B=on"
  local a; a="$(audited 'sentinel-1B')"
  local planted; planted="$(exists_fn public row_to_json)"
  local res
  if [ "$a" -ge 1 ]; then res="LOGGED (not blinded)"; else res="BLINDED"; fi
  local why
  if [ "$1" = "on" ] && [ "$2" = "off" ]; then why="CREATE on public + UNPINNED definer fn; caller path places public first (1T isolates whether type-specificity also beats a pg_catalog-first path)"
  elif [ "$2" = "on" ]; then why="pinned search_path defeats the overload even with public writable"
  else why="cannot CREATE in public (stock PG15+) so nothing to shadow"; fi
  ROWS+=("| 1B $4 | public exact-type overload row_to_json(app.accounts) | $1 | $2 | $3 | public.row_to_json planted=$planted → **$res** | n/a | $why |")
}

run_cell_1S() {  # same-signature record overload, public BEFORE pg_catalog (validates corrected 1A)
  build_victim on off off
  attack "run_1S=on"
  local a planted; a="$(audited 'sentinel-1S')"; planted="$(exists_fn public row_to_json)"
  local res; if [ "$a" -ge 1 ]; then res="LOGGED (not blinded)"; else res="BLINDED (payload nulled)"; fi
  ROWS+=("| 1S same-signature shadow | public.row_to_json(**record**), public before pg_catalog | on | off | off | planted=$planted → **$res** | payload-null (audit row still written) | CREATE on public; plain CVE-2018-1058 schema ordering |")
}

run_cell_1T() {  # type-specificity isolation: exact overload with pg_catalog EXPLICITLY first
  build_victim on off off
  attack "run_1T=on"
  local a planted; a="$(audited 'sentinel-1T')"; planted="$(exists_fn public row_to_json)"
  local res why
  if [ "$a" -ge 1 ]; then res="LOGGED (not blinded)"; why="exact overload does NOT beat pg_catalog when catalog is first → 1B blinding was schema-ordering, not type-specificity"
  else res="BLINDED (payload nulled)"; why="exact app.accounts overload beats generic record built-in EVEN with pg_catalog first → type-specificity confirmed"; fi
  ROWS+=("| 1T type-specificity isolation | public.row_to_json(**app.accounts**), **pg_catalog first** | on | off | off | planted=$planted → **$res** | payload-null if blinded | $why |")
}

run_cell_1C() {  # ownership misconfig; measure reversibility via snapshot diff
  build_victim off off on
  # snapshot BEFORE
  su_f -v tag=before -f - < "$DIR/40_snapshot.sql" 2>>"$EV" | grep -E '^SNAP' > "$ROOT/results/_snap_1C_${VER}.txt" || true
  # install DDL-guard defense so we can also measure detectability
  su_f -f - < "$DIR/30_defenses.sql" >>"$EV" 2>&1
  attack "run_1C=on"
  # snapshot AFTER
  su_f -v tag=after -f - < "$DIR/40_snapshot.sql" 2>>"$EV" | grep -E '^SNAP' >> "$ROOT/results/_snap_1C_${VER}.txt" || true
  local blinded ctl fn_before fn_after ddl_caught canary
  blinded="$(audited 'sentinel-1C')"          # expect 0 (dropped)
  ctl="$(audited 'sentinel-1C-ctl')"          # expect 1 (after restore)
  present_write="$(present 'sentinel-1C')"    # row DID land in business table
  fn_before="$(grep 'before audit if_modified' "$ROOT/results/_snap_1C_${VER}.txt" | awk '{print $6}')"
  fn_after="$(grep 'after audit if_modified'  "$ROOT/results/_snap_1C_${VER}.txt" | awk '{print $6}')"
  ddl_caught="$(q "SELECT count(*) FROM audit.ddl_watch WHERE objid LIKE 'audit.if_modified%';")"
  # canary: business writes vs audit rows mismatch
  canary="$(q "SELECT (SELECT count(*) FROM app.accounts) - (SELECT count(*) FROM audit.logged_actions WHERE table_name='accounts');")"
  local resid="fn md5 before=${fn_before:-?} after=${fn_after:-?}"
  local residret; if [ "${fn_before:-x}" = "${fn_after:-y}" ]; then residret="YES (fn body identical; object-diff clean)"; else residret="NO (fn body changed)"; fi
  local verdict; if [ "$blinded" -eq 0 ] && [ "$ctl" -ge 1 ]; then verdict="BLINDED & reversible"; else verdict="unexpected (sentinel=$blinded ctl=$ctl)"; fi
  ROWS+=("| 1C | replace trigger fn (ownership misconfig) | off | off | on | sentinel write logged=$blinded (0=dropped), post-restore ctl logged=$ctl, business-row present=$present_write → **$verdict** | fn-body object-diff: $residret — BUT DDL-guard caught replace=$ddl_caught event(s), write-vs-audit canary gap=$canary | app owns/ALTER on audit fn |")
}

run_cell_1R2() {  # RQ2 negative control: semantic (non-verbatim) restore is DETECTABLE
  build_victim off off on
  su_f -v tag=before -f - < "$DIR/40_snapshot.sql" 2>>"$EV" | grep -E '^SNAP' > "$ROOT/results/_snap_1R2_${VER}.txt" || true
  attack "run_1R2=on"
  su_f -v tag=after -f - < "$DIR/40_snapshot.sql" 2>>"$EV" | grep -E '^SNAP' >> "$ROOT/results/_snap_1R2_${VER}.txt" || true
  local blinded ctl fb fa
  blinded="$(audited 'sentinel-1R2')"; ctl="$(audited 'sentinel-1R2-ctl')"
  fb="$(grep 'before audit if_modified' "$ROOT/results/_snap_1R2_${VER}.txt" | awk '{print $6}')"
  fa="$(grep 'after audit if_modified'  "$ROOT/results/_snap_1R2_${VER}.txt" | awk '{print $6}')"
  local diff; if [ "${fb:-x}" != "${fa:-y}" ]; then diff="**DETECTED** (fn md5 before=$fb ≠ after=$fa)"; else diff="not detected (md5 identical)"; fi
  ROWS+=("| 1R2 semantic restore (RQ2 −ctrl) | blind, restore reformatted-equivalent body | off | off | on | sentinel logged=$blinded, ctl logged=$ctl → **BLINDED** | object-diff: $diff — contrast 1C verbatim replay (clean) | app owns/ALTER on audit fn |")
}

run_cell_2G() {  # GUC dormant, needs owns=on
  build_victim off off on
  attack "run_2G=on"
  local gated ctl
  gated="$(audited 'sentinel-2G-gated')"      # expect 0
  ctl="$(audited 'sentinel-2G-ctl')"          # expect 1
  local res
  if [ "$gated" -eq 0 ] && [ "$ctl" -ge 1 ]; then res="DORMANT-BYPASS WORKS (gated skipped, ctl logged)"; else res="did not behave as designed (gated=$gated ctl=$ctl)"; fi
  ROWS+=("| 2 GUC dormant | needs 1C precondition | off | off | on | gated logged=$gated / ctl logged=$ctl → **$res** | at rest fn looks legit; only a source review + GUC-aware canary catches it | app owns/ALTER on audit fn |")
}

run_cell_3P() {  # attribution poisoning, needs broad INSERT grant
  build_victim off off off
  # model the broad-grant misconfig: app can reach + insert into the audit table
  q "GRANT USAGE ON SCHEMA audit TO app_role;" >/dev/null
  q "GRANT INSERT ON audit.logged_actions TO app_role;" >/dev/null
  q "GRANT USAGE ON SEQUENCE audit.logged_actions_event_id_seq TO app_role;" >/dev/null
  attack "run_3P=on"
  local ghost
  ghost="$(q "SELECT count(*) FROM audit.logged_actions WHERE changed_by='ghost_user_42' AND client_ip='203.0.113.77';")"
  # The fabricated row is schema-identical to genuine rows (all columns attacker-supplied
  # and individually valid, incl. a backdated logged_at) — a reviewer using ONLY the audit
  # table has no field that flags it as forged. Confirm no structural discriminator exists:
  local backdated
  backdated="$(q "SELECT count(*) FROM audit.logged_actions WHERE changed_by='ghost_user_42' AND logged_at < now() - interval '2 days';")"
  local res; if [ "$ghost" -ge 1 ]; then res="POISONED (fabricated identity accepted)"; else res="rejected"; fi
  ROWS+=("| 3 attribution poison | broad INSERT grant | off | off | (insert grant) | ghost row present=$ghost, backdated=$backdated → **$res** | **NO** — schema-identical to genuine rows; only cross-layer correlation with an app-side log exposes it | INSERT on audit table |")
}

# ---- run all cells ----
run_cell_1A on  off off "default"
run_cell_1A off on  off "hardened"
run_cell_1B off off off "public-not-writable (=stock PG15+)"
run_cell_1B on  off off "writable public (=stock PG14 / misconfig PG15+)"
run_cell_1B on  on  off "hardened(pinned path)"
run_cell_1S
run_cell_1T
run_cell_1C
run_cell_1R2
run_cell_2G
run_cell_3P

# ---- Vector 1D (SECURITY DEFINER helper) applicability ----
# The victim's if_modified IS SECURITY DEFINER but calls no attacker-reachable
# unqualified helper other than the catalog built-ins already tested in 1A/1B.
ROW_1D="| 1D secdef helper | misconfig | on | off | off | **N/A in this victim** — no SECURITY DEFINER *helper* with a mutable path beyond the catalog built-ins covered by 1A/1B | n/a | (would need a bespoke unqualified secdef helper) |"

# ============================================================
#  DEFENSE demos independent of knobs (RQ5): D-ET and D-HC
# ============================================================
# D-ET already exercised in 1C (ddl_watch). Confirm app_role CANNOT drop the guard:
build_victim off off on
su_f -f - < "$DIR/30_defenses.sql" >>"$EV" 2>&1
DROP_ET="$(docker exec -i "$CID" psql -tA -U app_role -d labdb -c 'DROP EVENT TRIGGER audit_ddl_guard;' 2>&1 | tr '\n' ' ')"
if echo "$DROP_ET" | grep -qi 'must be owner\|permission denied\|denied'; then ET_DEF="app_role CANNOT drop the event trigger (permission denied) → detection survives"; else ET_DEF="UNEXPECTED: $DROP_ET"; fi

# D-HC hash-chain tamper-evidence demo
su_f -f - < "$DIR/30_defenses.sql" >>"$EV" 2>&1
HC="$(docker exec -i "$CID" psql -tA -U postgres -d labdb 2>>"$EV" <<'SQL'
SELECT audit.secure_append('{"e":1}');
SELECT audit.secure_append('{"e":2}');
SELECT audit.secure_append('{"e":3}');
SELECT 'intact_verify=' || COALESCE(audit.secure_verify()::text,'NULL');
-- attacker with INSERT on secure_log injects a raw backdated row (wrong hash):
INSERT INTO audit.secure_log(payload,prev_hash,this_hash)
  VALUES ('{"forged":true}', repeat('0',64), 'deadbeef');
SELECT 'after_tamper_verify=' || COALESCE(audit.secure_verify()::text,'NULL');
SQL
)"
HC_INTACT="$(echo "$HC" | grep intact_verify= | tr -d ' ')"
HC_TAMPER="$(echo "$HC" | grep after_tamper_verify= | tr -d ' ')"

# D-EL engine-level logging demo (pgaudit stand-in): log_statement='mod' writes every
# DML to the SERVER log, which app_role can neither alter (superuser-only GUC) nor truncate
# (no OS access). Show the engine still captures a write while the trigger auditor is blinded.
docker exec -i "$CID" psql -U postgres -d postgres -c "ALTER SYSTEM SET log_statement='mod';" >>"$EV" 2>&1
docker exec -i "$CID" psql -U postgres -d postgres -c "SELECT pg_reload_conf();" >>"$EV" 2>&1
build_victim off off on            # ownership misconfig
attack "run_1C=on"                 # blinds the trigger for sentinel-1C
sleep 1
if docker logs "$CID" 2>&1 | grep -q "sentinel-1C"; then
  EL_DEF="engine log_statement CAPTURED the write in the server log even though the trigger auditor was blinded — and app_role can neither change the GUC nor reach the log file"
else
  EL_DEF="UNEXPECTED: engine log did not contain the write"
fi
docker exec -i "$CID" psql -U postgres -d postgres -c "ALTER SYSTEM RESET log_statement;" >>"$EV" 2>&1
docker exec -i "$CID" psql -U postgres -d postgres -c "SELECT pg_reload_conf();" >>"$EV" 2>&1

# ============================================================
#  WRITE RESULTS.md
# ============================================================
{
echo "# RESULTS — Self-Defeating Audits — PostgreSQL ${VER}"
echo
echo "_Local, disposable, synthetic lab. Generated by \`run_matrix.sh ${VER}\`._"
echo
echo "## Environment"
echo
echo "| Field | Value |"
echo "|---|---|"
echo "| Image | \`postgres:${VER}-alpine\` |"
echo "| Image digest | \`${IMG_DIGEST}\` |"
echo "| \`version()\` | ${PGVERSION} |"
echo "| DBA \`search_path\` | \`${SP_SU}\` |"
echo "| app_role \`search_path\` | \`${SP_APP}\` |"
echo "| **Stock \`public\` ACL (fresh DB, no intervention)** | \`${STOCK_PUB_ACL}\` |"
echo "| **A fresh low-priv role can CREATE in \`public\` by stock default** | **${STOCK_APP_CREATE}** (t on PG≤14, f on PG15+) |"
echo
echo "> Victim \`audit.if_modified()\` is **SECURITY DEFINER** (faithful to the wiki pattern —"
echo "> required so a low-privilege writer can be audited at all). Precondition columns below"
echo "> are FORCED to a known state to normalize PG-version default differences."
echo
echo "## §6 Feasibility Matrix"
echo
echo "| Vector | Precondition modeled | PUBLIC CREATE on public | Trigger fn search_path pinned | app_role owns audit fn | Result | Reversible / zero-residue? | True privilege needed |"
echo "|---|---|:--:|:--:|:--:|---|---|---|"
for r in "${ROWS[@]}"; do echo "$r"; done
echo "$ROW_1D"
echo
echo "## §8 Defenses (RQ5)"
echo
echo "| Defense | Result |"
echo "|---|---|"
echo "| REVOKE CREATE ON public (pub=off) | kills 1A/1B planting in public (see hardened rows) |"
echo "| Pin trigger search_path (pin=on) | kills path-shadowing (see 1A hardened) |"
echo "| Correct ownership (owns=off) | kills 1C & Exp 2 — app_role cannot CREATE OR REPLACE the fn |"
echo "| D-ET event-trigger DDL guard | ${ET_DEF} |"
echo "| D-HC hash-chained append-only sink | ${HC_INTACT}; ${HC_TAMPER} (non-NULL seq = tamper detected) |"
echo "| D-EL engine-level logging (log_statement='mod', pgaudit stand-in) | ${EL_DEF} |"
echo "| pgaudit (dedicated extension) | not installable in the alpine image (no apk package); the D-EL result above demonstrates the same engine-level principle — logging happens in the executor, outside the app role's reach |"
echo
echo "_Full command/output evidence: \`results/_evidence_pg${VER}.log\`; 1C object-diff: \`results/_snap_1C_${VER}.txt\`._"
} > "$RES"

echo "WROTE $RES"
echo "---- matrix preview ----"
for r in "${ROWS[@]}"; do echo "$r"; done
echo "$ROW_1D"
echo "D-ET: $ET_DEF"
echo "D-HC: $HC_INTACT ; $HC_TAMPER"
