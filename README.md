# Self-Defeating Audits — reproducible lab

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22004478.svg)](https://doi.org/10.5281/zenodo.22004478)
&nbsp;License: MIT (code) / CC BY 4.0 (docs)

Defensive-security research testing whether a **low-privilege, injection-only** database
role can **reversibly blind a trigger-based auditor** and **poison attribution** on stock
PostgreSQL — and which defenses actually stop it. Everything runs in **disposable, local
Docker containers** with **entirely synthetic data** (RFC 5737 documentation IPs, invented
identities). No real systems, credentials, or data are involved.

See the lab brief in [`self-defeating-audits-lab.md`](self-defeating-audits-lab.md).

## What it does

Builds the widely-copied PostgreSQL wiki "audit trigger" victim, then works a
**feasibility matrix** cell-by-cell across **PostgreSQL 14 and 16**, measuring — out of
band — whether each attack vector actually stops a write from being audited, whether it is
reversible with zero residue, and which defenses kill it.

## Run it

```bash
cd scripts
./00_up.sh 16          # bring up postgres:16-alpine on localhost:55432
./run_matrix.sh 16     # run every matrix cell + defenses -> ../results/RESULTS_pg16.md
docker rm -f sda_pg16  # free the port between versions
./00_up.sh 14
./run_matrix.sh 14     # -> ../results/RESULTS_pg14.md
./teardown.sh          # remove all lab containers
```

Requires Docker. Uses the `-alpine` images (functionally identical engine).

## Cross-engine (MySQL family + SQL Server)

The study is reproduced on two more engine families. **MySQL family** (MariaDB,
`DEFINER`-trigger model) under `scripts/mysql/`:

```bash
cd scripts/mysql
./00_up.sh 10.11 && ./run_matrix_mysql.sh 10.11   # -> results/RESULTS_mariadb_10.11.md
docker rm -f sda_maria_10_11 && ./00_up.sh 10.6 && ./run_matrix_mysql.sh 10.6
```

**SQL Server** (ownership-chaining model) under `scripts/mssql/` — runs on a local
LocalDB instance via host `sqlcmd` (no Docker; the low-priv attacker is modelled with
`EXECUTE AS USER` impersonation):

```bash
cd scripts/mssql
./run_matrix_mssql.sh        # -> results/RESULTS_mssql.md ; then ./teardown.sh
```

Headline cross-engine result: the `search_path` shadow class (1A/1B) **transfers to
neither** MySQL nor SQL Server (no `search_path`), but trigger-replacement, dormant
bypass, and attribution poisoning do. MySQL's `DEFINER`-privilege binding makes blinding
**more detectable**; SQL Server, like PostgreSQL, allows byte-perfect restore and adds a
**zero-residue `DISABLE TRIGGER`** primitive its own DDL defense misses. Full three-engine
comparison in `FINDINGS.md`.

## Layout

| Path | What |
|---|---|
| `scripts/00_up.sh` | version-pinned throwaway container (PostgreSQL) |
| `scripts/mysql/` | MySQL-family (MariaDB) victim, attacks, defenses, and orchestrator |
| `scripts/mssql/` | SQL Server (LocalDB) victim, attacks, defenses, and orchestrator |
| `results/RESULTS_mariadb_*.md` | MySQL-family feasibility + defense matrices |
| `results/RESULTS_mssql.md` | SQL Server feasibility + defense matrix |
| `scripts/10_victim.sql` | the wiki-pattern audit victim (SECURITY DEFINER trigger); knobs: `pub_create`, `pin_path`, `app_owns` |
| `scripts/20_attacks.sql` | all attack vectors (1A/1B/1C, GUC dormant, attribution poison), one `\if`-guard per cell |
| `scripts/30_defenses.sql` | DDL event-trigger guard + hash-chained append-only sink |
| `scripts/40_snapshot.sql` | catalog snapshot for the RQ2 object-diff |
| `scripts/run_matrix.sh` | orchestrator: builds each cell, measures, writes `results/RESULTS_pg<VER>.md` |
| `scripts/teardown.sh` | remove containers |
| `results/RESULTS_pg14.md`, `results/RESULTS_pg16.md` | filled feasibility + defense matrices per version |
| `results/_evidence_pg*.log`, `results/_snap_1C_*.txt` | raw command/output evidence |
| `FINDINGS.md` | plain-English RQ1–RQ5 verdict, defense×attack matrix, novelty positioning, abstract |

## Headline result

- **1A** plain catalog shadowing — **fails** (as predicted; `pg_catalog` wins).
- **1B** exact composite-type `row_to_json` overload — **blinds** the auditor when
  `public` is writable and the trigger `search_path` is unpinned. **Reachable on stock
  PostgreSQL ≤14; misconfiguration-gated on 15+.** Pinning `search_path` defeats it everywhere.
- **1C** replacing an app-owned audit function — **blinds, and is reversible with a clean
  object-diff** (verbatim source replay) — yet a write-vs-audit **canary** and a **DDL
  event-trigger** still catch it.
- **GUC-gated dormancy** and **in-database attribution poisoning** both work under their
  (misconfig) preconditions; the fabricated audit row is indistinguishable from the audit
  table alone.
- **Engine-level logging** (`pgaudit`/`log_statement`) + **hash-chained sink** are the
  defenses that close the set.

## Responsible-disclosure posture

Reproduced on **stock PostgreSQL in a local lab with anonymized/synthetic data**. The
attack SQL is scoped to the lab schema built here; this is a feasibility/defense study, not
a weaponized payload. The underlying primitives are already public (CVE-2018-1058;
SECURITY DEFINER `search_path` escalation) — the contribution is the *composition* and the
*defense evaluation*. No real system is identified.
