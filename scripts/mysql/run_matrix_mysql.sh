#!/usr/bin/env bash
# run_matrix_mysql.sh — MySQL-family (MariaDB) feasibility + defense matrix.
# Usage: ./run_matrix_mysql.sh [VER]   (default 10.11)
# Produces results/RESULTS_mariadb_<VER>.md and results/_evidence_mariadb_<VER>.log
set -uo pipefail
VER="${1:-10.11}"
CID="sda_maria_${VER//./_}"
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
RES="$ROOT/results/RESULTS_mariadb_${VER}.md"
EV="$ROOT/results/_evidence_mariadb_${VER}.log"
: > "$EV"

rootf(){ docker exec -e MYSQL_PWD=labonly_rootpw -i "$CID" mysql -uroot "$@"; }        # -f files/stmts as root
appf(){  docker exec -e MYSQL_PWD=app_pw        -i "$CID" mysql -uapp_user --force "$@"; } # attacks (tolerant)
rq(){    docker exec -e MYSQL_PWD=labonly_rootpw -i "$CID" mysql -uroot -N -B -e "$1" 2>>"$EV"; } # scalar
log(){ echo -e "$@" >>"$EV"; }

build_victim(){ log "\n=== BUILD VICTIM ==="; rootf < "$DIR/10_victim.sql" >>"$EV" 2>&1; }
grant_trigger(){ rq "GRANT TRIGGER ON labdb.app_accounts TO 'app_user'@'%';"; }
grant_audit_insert(){ rq "GRANT INSERT ON labdb.audit_logged_actions TO 'app_user'@'%';"; }
run_atk(){ log "\n--- ATTACK $1 ---"; appf labdb < "$DIR/$1" >>"$EV" 2>&1; }
audited(){ rq "SELECT COUNT(*) FROM labdb.audit_logged_actions WHERE JSON_UNQUOTE(JSON_EXTRACT(row_data,'\$.holder'))='$1';"; }
trig_def(){ rq "SELECT COALESCE(GROUP_CONCAT(CONCAT(TRIGGER_NAME,':',DEFINER) ORDER BY TRIGGER_NAME SEPARATOR ' | '),'(none)') FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='labdb' AND EVENT_OBJECT_TABLE='app_accounts';"; }

echo "############ MariaDB ${VER} — MySQL-family matrix ############"
IMG_DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' mariadb:${VER} 2>/dev/null || echo n/a)"
DBVER="$(rq 'SELECT VERSION();')"

declare -a ROWS

# ---- FN: search_path/catalog-shadow analogue (expected N/A) ----
build_victim
run_atk atk_fn.sql
FN_LOG="$(audited 'sentinel-FN')"
FN_SHADOW="$(rq "SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='labdb' AND ROUTINE_NAME LIKE 'JSON_OBJECT%';")"
ROWS+=("| FN function/catalog shadow | app tries to shadow the capture built-in | **N/A** — no search_path; built-in JSON_OBJECT is not shadowable and app lacks CREATE ROUTINE (planted routines=$FN_SHADOW) → write still audited (logged=$FN_LOG) | — | the entire PG 1A/1B class does not transfer |")

# ---- 1C: trigger replacement (needs TRIGGER priv) ----
build_victim; grant_trigger
SNAP_BEFORE="$(trig_def)"
run_atk atk_1c.sql
SNAP_AFTER="$(trig_def)"
C_BLIND="$(audited 'sentinel-1C')"; C_CTL="$(audited 'sentinel-1C-ctl')"
ROOT_DEF_AI="$(rq "SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='labdb' AND TRIGGER_NAME='accounts_ai' AND DEFINER='root@localhost';")"
verdict1c="BLINDED"; [ "$C_BLIND" -ge 1 ] && verdict1c="NOT blinded (logged=$C_BLIND)"
restore="restore to root-DEFINER FAILED (app cannot set DEFINER=root); AFTER INSERT root-definer trigger present now=$ROOT_DEF_AI → residue remains"
ROWS+=("| 1C replace trigger | app has TRIGGER priv on the table | **$verdict1c** (sentinel logged=$C_BLIND, ctl logged=$C_CTL) | $restore | TRIGGER privilege on the table |")

# ---- 2G: dormant session-variable gate (needs TRIGGER + audit INSERT) ----
build_victim; grant_trigger; grant_audit_insert
run_atk atk_2g.sql
G_GATED="$(audited 'sentinel-2G-gated')"; G_CTL="$(audited 'sentinel-2G-ctl')"
verdict2g="did not behave as designed (gated=$G_GATED ctl=$G_CTL)"
[ "$G_GATED" -eq 0 ] && [ "$G_CTL" -ge 1 ] && verdict2g="DORMANT-BYPASS WORKS (gated skipped, ctl logged)"
ROWS+=("| 2 GUC/session dormant | TRIGGER priv AND audit-INSERT grant | **$verdict2g** (gated logged=$G_GATED / ctl logged=$G_CTL) | at rest looks legit; **needs the extra audit-INSERT grant** (harder than PostgreSQL) | TRIGGER priv + INSERT on audit table |")

# ---- 3P: attribution poisoning (needs audit INSERT) ----
build_victim; grant_audit_insert
run_atk atk_3p.sql
P_GHOST="$(rq "SELECT COUNT(*) FROM labdb.audit_logged_actions WHERE changed_by LIKE 'ghost_user_42%';")"
P_BACK="$(rq "SELECT COUNT(*) FROM labdb.audit_logged_actions WHERE changed_by LIKE 'ghost_user_42%' AND logged_at < NOW() - INTERVAL 2 DAY;")"
verdict3p="rejected"; [ "$P_GHOST" -ge 1 ] && verdict3p="POISONED (fabricated identity accepted)"
ROWS+=("| 3 attribution poison | broad INSERT grant on audit table | **$verdict3p** (ghost=$P_GHOST, backdated=$P_BACK) | **NO** — schema-identical to genuine rows; needs cross-layer correlation | INSERT on audit table |")

# ============ DEFENSES ============
# D-PRIV: no TRIGGER privilege -> 1C cannot even drop/replace the trigger
build_victim   # (no grant_trigger)
run_atk atk_1c.sql
DPRIV_LOG="$(audited 'sentinel-1C')"
DPRIV="app_user without TRIGGER priv cannot DROP/replace the audit trigger → write still logged (logged=$DPRIV_LOG)"

# D-EL: engine-level general query log captures a write even while the trigger is blinded
build_victim; grant_trigger
rq "SET GLOBAL log_output='TABLE'; SET GLOBAL general_log='ON';"
rq "TRUNCATE mysql.general_log;"   # so the count reflects only this run
run_atk atk_1c.sql                 # blinds the trigger, writes sentinel-1C (+ ctl)
EL_HIT="$(rq "SELECT COUNT(*) FROM mysql.general_log WHERE CONVERT(argument USING utf8) LIKE '%sentinel-1C%' AND CONVERT(argument USING utf8) NOT LIKE '%general_log%';")"
rq "SET GLOBAL general_log='OFF';"
DEL="general query log CAPTURED the blinded write (matches=$EL_HIT) in an engine log app_user cannot read or purge"

# D-HC: hash-chained sink tamper-evidence
build_victim
rootf < "$DIR/30_defenses.sql" >>"$EV" 2>&1
HC="$(rootf -N -B labdb 2>>"$EV" <<'SQL'
CALL secure_append('{"e":1}'); CALL secure_append('{"e":2}'); CALL secure_append('{"e":3}');
SELECT CONCAT('intact=', IFNULL(CAST(secure_verify() AS CHAR),'NULL'));
INSERT INTO secure_log(payload,prev_hash,this_hash) VALUES('{"forged":true}',REPEAT('0',64),'deadbeef');
SELECT CONCAT('tampered=', IFNULL(CAST(secure_verify() AS CHAR),'NULL'));
SQL
)"
HC_INTACT="$(echo "$HC" | grep -o 'intact=[A-Za-z0-9]*')"
HC_TAMPER="$(echo "$HC" | grep -o 'tampered=[A-Za-z0-9]*')"

# ============ WRITE RESULTS ============
{
echo "# RESULTS — Self-Defeating Audits — MariaDB ${VER} (MySQL family)"
echo
echo "_Local, disposable, synthetic lab. Generated by \`run_matrix_mysql.sh ${VER}\`._"
echo
echo "## Environment"
echo
echo "| Field | Value |"
echo "|---|---|"
echo "| Image | \`mariadb:${VER}\` |"
echo "| Image digest | \`${IMG_DIGEST}\` |"
echo "| \`VERSION()\` | ${DBVER} |"
echo "| Binary log | enabled (\`--log-bin\`); \`log_bin_trust_function_creators=1\` |"
echo
echo "> Victim triggers are **DEFINER=\`root\`** (run with the definer's privileges — the MySQL"
echo "> analogue of SECURITY DEFINER), so a low-privilege writer can be audited. MySQL has **no"
echo "> \`search_path\`**, so the PostgreSQL 1A/1B catalog-shadow class does not transfer."
echo
echo "## Feasibility matrix"
echo
echo "| Vector | Precondition | Result | Reversible / residue | True privilege needed |"
echo "|---|---|---|---|---|"
for r in "${ROWS[@]}"; do echo "$r"; done
echo
echo "**1C trigger snapshot (object diff):**"
echo '```'
echo "before: ${SNAP_BEFORE}"
echo "after : ${SNAP_AFTER}"
echo '```'
echo
echo "## Defenses"
echo
echo "| Defense | Result |"
echo "|---|---|"
echo "| Remove TRIGGER privilege from app account | ${DPRIV} |"
echo "| Separate DEFINER (app cannot set DEFINER=root) | app-created triggers cannot impersonate root; the DEFINER change is an un-erasable residue (see 1C) |"
echo "| Engine log (general_log; pgaudit/binlog analogue) | ${DEL} |"
echo "| Hash-chained append-only sink | ${HC_INTACT}; ${HC_TAMPER} (non-NULL seq = tamper detected) |"
echo "| \`log_bin_trust_function_creators=0\` + binlog | incidental barrier — blocks non-SUPER trigger creation entirely (not exercised here; set to 1 to isolate the TRIGGER-privilege variable) |"
echo
echo "_Evidence: \`results/_evidence_mariadb_${VER}.log\`._"
} > "$RES"

echo "WROTE $RES"; echo "---- preview ----"; for r in "${ROWS[@]}"; do echo "$r"; done
echo "D-PRIV: $DPRIV"; echo "D-EL: $DEL"; echo "D-HC: $HC_INTACT ; $HC_TAMPER"
echo "1C snapshot before: $SNAP_BEFORE"; echo "1C snapshot after : $SNAP_AFTER"
