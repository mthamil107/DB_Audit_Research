# Self-Defeating Audits — reproducible lab

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

## Layout

| Path | What |
|---|---|
| `scripts/00_up.sh` | version-pinned throwaway container |
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
