# FINDINGS — Self-Defeating Audits

_Plain-English verdict from the reproducible lab (`scripts/`, results in `results/`).
Reproduced on stock **PostgreSQL 14.24** and **16.14** (`-alpine`), local disposable
containers, entirely synthetic data (RFC 5737 documentation IPs, invented identities)._

The victim is the widely-copied PostgreSQL wiki "audit trigger" pattern: an
`AFTER` row trigger calling a **`SECURITY DEFINER`** function `audit.if_modified()`
that captures each write via an **unqualified `row_to_json()`** and inserts it into a
DBA-owned `audit.logged_actions`. (The function must be `SECURITY DEFINER` for a
low-privilege writer to be audited at all — that is faithful to real deployments, and
it is precisely the CVE-2018-1058 surface.) The attacker is the **app role**, reached
via SQL injection: `SELECT/INSERT/UPDATE/DELETE` on business tables, **no superuser, no
OS access**, and no rights over the audit objects unless a matrix cell explicitly models
a misconfiguration.

---

## Verdicts by research question

### RQ1 — Feasibility (the crux): can the app role make the auditor stop recording a write?

**Answer: yes, but only under specific, nameable preconditions — never by plain
catalog shadowing on defaults.** The feasibility matrix (both PG versions identical in
behavior) splits cleanly:

| Vector | Blinds a write? | Precondition it truly needs |
|---|---|---|
| **1A** plant a shadow in a *new* schema `evil` | **No — blocked at setup** | The app role **cannot `CREATE SCHEMA`** without `CREATE`-on-database, so no shadow is ever planted. *This is a privilege barrier, not a name-resolution fact* — see the corrected note below. |
| **1S** same-signature `public.row_to_json(record)`, `public` before `pg_catalog` | **Yes (payload-nulled)** | Writable `public` + unpinned trigger path. Plain CVE-2018-1058 schema-ordering: a like-named object in an earlier schema shadows the built-in. |
| **1T** exact overload `public.row_to_json(app.accounts)`, **`pg_catalog` explicitly first** | **Yes (payload-nulled)** | Writable `public` + unpinned path. Isolates *type-specificity*: the exact rowtype overload beats the generic `row_to_json(record)` built-in **even when `pg_catalog` is searched first** — best-type-match precedes schema-order tie-breaking. |
| **1B** exact overload with `public` first | **Yes (payload-nulled)** | The convenience case combining both (writable `public`, unpinned path). |
| **1C** replace the trigger function body | **Yes (no record at all)** | The app role **owns / can `ALTER`** the audit function (ownership misconfig). |
| **1D** `SECURITY DEFINER` *helper* with mutable path | **N/A here** | No such bespoke helper exists in this victim beyond the built-ins covered above. |

**Corrected 1A note (this replaces an earlier, wrong explanation).** An earlier draft said 1A
fails because "`pg_catalog` is resolved first, so a same-name built-in cannot be shadowed."
**That is wrong and contradicts CVE-2018-1058** — a like-named object in a schema that *precedes*
`pg_catalog` on the path *does* shadow the built-in. The empirical truth (evidence logs): 1A fails
only because a fresh role cannot `CREATE SCHEMA` (privilege barrier). When the attacker instead
plants into the already-writable `public` schema, shadowing **succeeds** — demonstrated by **1S**
(same-signature, schema-ordering) and, more strongly, **1T** (exact overload beats the built-in
even with `pg_catalog` first, isolating type-specificity).

**Two kinds of "blinding" — do not conflate.** The overload vectors (1S/1T/1B) make
`row_to_json` return `NULL`, so an audit row is **still written** (correct `changed_by`, IP,
timestamp) but with a **null payload** — *payload-nulling*. Vector 1C leaves **no audit row at
all**. Both defeat payload capture; only 1C defeats the fact-of-a-write.

**The decisive version nuance (verified):**
- Stock **PostgreSQL 14**: a fresh low-privilege role **can** `CREATE` in `public` by
  default (`public` ACL = `… =UC/…`). So **1B blinding is reachable on stock PG14 defaults.**
- Stock **PostgreSQL 15+/16**: the default was changed — PUBLIC no longer has `CREATE`
  on `public` (ACL = `… =U/…`). So **1B requires an explicit misconfiguration on PG16.**

So the honest RQ1 headline is: **"On stock PostgreSQL ≤14 a SQL-injected app role can
blind a wiki-pattern audit trigger by planting an exact-type `row_to_json` overload in
the writable `public` schema; on PG15+ this needs a re-granted `public` or another
writable schema on the function's path. Pinning the trigger's `search_path` defeats it
on every version."** The stronger structural claim (1C) needs an ownership
misconfiguration, which is common but is a misconfiguration, not a default.

### RQ2 — Reversibility / anti-forensics: can the attacker restore so an object-diff sees nothing?

**Answer: yes for the function body specifically — but independent controls still catch
it.** In 1C the attacker first captures the exact original source (`pg_proc.prosrc` is
world-readable and stored **verbatim**), blinds one write with a no-op body, then replays
the captured definition byte-for-byte. Result: **`pg_get_functiondef` md5 before == after
— a source/object diff finds nothing.** (Note: a *naive* restore that merely rewrites a
semantically-identical body does **not** match, because the source is stored verbatim —
so casual reversibility is detectable; careful reversibility is not.)

What still betrays it, even after a perfect body restore:
- the **write-vs-audit canary** (business-table row count minus audit row count) shows a
  **gap of 1** — the blinded write left a hole;
- the **DDL event-trigger guard** recorded **2** `CREATE OR REPLACE FUNCTION` events on
  `audit.if_modified` (blind + restore).

**Negative control (1R2) — semantic restore *is* detectable.** A careless attacker who
restores a *behaviourally-identical but reformatted* body (rather than replaying captured
bytes) leaves a **different `pg_proc.prosrc`**: the function md5 changes (measured:
`66cf56bc… → bab9fc81…`), so an object diff **catches** it. This isolates the earlier claim: it
is specifically the *verbatim capture-and-replay* (1C) that defeats object-diffing, not restoration
in general. So the reversibility result is not a tautology — it is the contrast between 1C (clean)
and 1R2 (detected).

So RQ2's lesson: **object-diffing the audit code catches a naive restore but is defeated by a
verbatim replay; you therefore also need an out-of-band write counter and a DDL event log.**

> **Significance framing (honest).** Only the **overload class (1S/1T/1B)** bites a role holding
> nothing but application privileges, and only on a *writable `public`* (stock on PostgreSQL ≤14;
> a misconfiguration on 15+). **1C, RQ3, and RQ4 all presuppose an audit-object misconfiguration**
> — the app role already **owns/can `ALTER`** the audit function or can **`INSERT`** into the audit
> table. Their contribution is therefore not "tampering is possible" (that is expected once you
> control the auditor) but *what that misconfiguration additionally unlocks*: **reversibility with a
> clean object-diff, session-gated dormancy, and forensically-indistinguishable attribution
> poisoning** — plus how detectable each is, which differs sharply across engines (next section).

### RQ3 — Dormant, GUC-gated bypass

**Answer: yes (given the 1C ownership precondition).** A `current_setting('app.maint')`
branch grafted into the real function skips logging **only** in a session that sets the
flag: the gated write was **not** logged, a control write in the same session **was**.
At rest the function *looks* legitimate — only a source review or a GUC-aware canary
distinguishes it. Treat this as **supporting evidence** (a known-style backdoor pattern),
not a standalone novelty.

### RQ4 — Attribution poisoning from within

**Answer: yes (given a broad `INSERT` grant on the audit table).** The app role wrote a
fully fabricated row — non-existent user `ghost_user_42`, synthetic IP `203.0.113.77`
(RFC 5737), **backdated three days** — directly into `audit.logged_actions`. It is
**schema-identical to genuine rows**: a reviewer using *only* the audit table has **no
field that flags it as forged**. Exposure requires **cross-layer correlation** with an
independent app-side log. This motivates out-of-engine logging and tamper-evidence.

### RQ5 — Which defenses actually stop each attack

Every defense below was executed, not asserted:

| Defense (column) →<br>Attack (row) ↓ | REVOKE CREATE on `public` | Pin trigger `search_path` | Correct ownership (app can't ALTER fn) | DDL event-trigger guard | Hash-chained append-only sink | Engine log (`log_statement`/pgaudit) |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| **1B** overload shadow | **stops** | **stops** | — | detects DDL* | — | logs write |
| **1C** replace fn | — | — | **stops** | **detects** | — | logs write |
| **2** GUC dormant | — | — | **stops** | **detects** the graft | — | logs write |
| **3** attribution poison | — | — | — | — | **exposes** (chain break / no chain entry) | corroborates real actor |

\* the overload plant is a `CREATE FUNCTION` in `public`, not on an `audit.*` object, so
the audit-scoped DDL guard as written targets `audit.*`; widen its filter to catch
public-schema plants too.

Empirical defense results (both versions):
- **Pin the trigger `search_path`** (`ALTER FUNCTION … SET search_path = pg_catalog, audit`)
  — 1B goes from **BLINDED** to **LOGGED** even with `public` writable. Single most
  effective one-line fix for the shadowing class.
- **`REVOKE CREATE ON SCHEMA public FROM PUBLIC`** — removes the 1B plant site
  (already the PG15+ default).
- **Correct ownership** (audit fn owned by a dedicated role the app can never `ALTER`)
  — the app role **cannot** `CREATE OR REPLACE` the function, killing **1C and Exp 2**.
- **DDL event-trigger guard** — app role **cannot drop** it (permission denied); it
  recorded the 1C replacements. Detective, not preventive.
- **Hash-chained append-only sink** — a raw/backdated insert breaks
  `secure_verify()` (returned the tampered `seq`; an intact chain returns NULL),
  giving cryptographic tamper-evidence against Exp 3.
- **Engine-level logging** (`log_statement='mod'` as a pgaudit stand-in) — captured the
  write in the **server log** even while the trigger auditor was blinded; the app role
  can neither change the GUC (superuser-only) nor reach the log file (no OS access).
  This is the recommended fix and confirms the deep-research expectation that engine-level
  auditing is outside the app role's reach. (Dedicated `pgaudit` was not installable in
  the alpine image; the principle is identical.)

---

## Cross-engine generalization (MySQL family + SQL Server)

We reproduced the study on two more engine families to test whether "self-defeating audits" is
PostgreSQL-specific: the **MySQL family** (MariaDB 10.6 and 10.11) and **SQL Server** (LocalDB,
SQL Server 2025 / v17). The composition transfers to all three, but the exploitation surface and
reversibility differ by engine — which is itself the finding.

| Aspect | PostgreSQL (14/16) | MySQL family (MariaDB 10.6/10.11) | SQL Server (2025 / v17) |
|---|---|---|---|
| **"Definer" mechanism** | `SECURITY DEFINER` function | `DEFINER` trigger | ownership chaining (`EXECUTE AS` also available) |
| **Shadow class (1A/1B)** | **blinds on stock PG≤14** (writable `public` + unpinned `search_path`) | **N/A** — no `search_path`; built-ins unshadowable | **N/A** — no `search_path`; unqualified names in a `dbo` module resolve in `dbo` |
| **Precondition for replacement** | app owns the audit function | app has `TRIGGER` priv on the table | app has `ALTER` on the table |
| **Trigger/fn replacement (1C)** | blinds; **byte-perfect verbatim restore** → clean object diff | blinds; **cannot restore** the `root`-DEFINER trigger (no `SET USER`/`SUPER`) → missing-trigger residue | blinds; **byte-perfect verbatim restore** → clean object diff (like PG) |
| **Extra blinding primitive** | — | — | **`DISABLE TRIGGER`** — zero-residue, reversible, definition unchanged |
| **Dormant bypass** | **easy** (DEFINER fn alone) | **harder** — needs an extra audit-`INSERT` grant | **easy** — `ALTER` keeps `dbo` ownership → chaining survives (like PG) |
| **Attribution poisoning** | fabricated, backdated, indistinguishable | identical | identical |
| **Engine-level defense** | pgaudit / `log_statement` | `general_log` / binary log | SQL Server Audit |
| **Detection nuance** | DDL event trigger catches the replace | object-diff exposes the missing/altered trigger | DDL trigger catches `ALTER` but **NOT `DISABLE`** (gap) |

**Cross-engine thesis:** the *self-defeating-audit* threat — an auditee at application privilege
blinding an unaudited in-engine auditor, plus dormant bypass and attribution poisoning — is a
**three-engine class**, not a PostgreSQL quirk. PostgreSQL and SQL Server form the *permissive*
pair (verbatim-restore reversibility and easy dormancy), while the **MySQL family is the most
tamper-evident** because its `DEFINER`-privilege binding stops the attacker from restoring the
original trigger. PostgreSQL is uniquely exposed on *stock defaults* (name-resolution shadowing on
PG≤14); SQL Server uniquely adds a **zero-residue `DISABLE TRIGGER`** primitive whose blinding its
own DDL-trigger defense does not catch. The common core — never trust an in-engine trigger log as
tamper-proof against the role it audits; require engine-level plus out-of-engine tamper-evidence —
holds identically on all three.

## Novelty positioning (from the verified deep-research pass)

**Cite as prior art — do not claim:**
- `search_path` shadowing of `pg_catalog` built-ins by a non-superuser — **CVE-2018-1058**
  (CVSS 8.8, PR:L; fixed 2018-03-01). This is exactly vectors 1A/1B at the primitive level.
- `SECURITY DEFINER` search_path privilege-escalation class — CVE-2007-2138,
  CVE-2020-25695, and vendor guidance ("Writing SECURITY DEFINER Functions Safely").
- The canonical defenses (pin `search_path` to empty / schema-qualify /
  `REVOKE CREATE ON public`; PG15 made the last one default).
- Tamper-evidence requiring an incorruptible auditor and hash-chaining
  (Crosby & Wallach, USENIX Security 2009) — grounds RQ2/Exp 3.

**Genuinely novel / under-explored (the defensible contribution):**
- **Threat-model inversion.** Published DB anti-forensics assumes a *privileged*
  adversary (superuser/DBA editing logs — e.g. MemTraceDB, arXiv:2509.05891). A
  **low-privilege, injection-only app role reversibly blinding an *unaudited* auditor**
  is not in the literature.
- **Composition:** reversible auditor-blinding **+** GUC-gated dormancy (RQ3) **+**
  in-database attribution poisoning (RQ4) as one coherent "self-defeating audit" threat —
  no prior source covers RQ3/RQ4 at all.
- **The verbatim-restore observation** (RQ2): source is stored byte-for-byte, so casual
  restore is detectable but a capture-and-replay restore is not — object-diffing audit
  code is therefore insufficient by itself.

**Publishable strength: ★★★★** — "reversible auditor-blinding by the auditee at
application privilege, plus dormancy and attribution poisoning," **positioned against the
primitives it composes.** The ★★★★★ "structural on stock defaults" claim survives **only
for PostgreSQL ≤14** (writable `public` by default); on PG15+ it is misconfiguration-gated.
State the PostgreSQL version and the `public`-schema ACL for every claim.

---

## One-paragraph abstract-ready summary

On the widely-copied PostgreSQL wiki audit-trigger pattern, a SQL-injected application
role — with no superuser and no OS access — can reversibly blind the trigger-based
auditor and poison attribution from *within* the database. Planting an exact composite-type
`row_to_json` overload in a writable `public` schema silently nulls captured rows against an
unpinned `SECURITY DEFINER` trigger (reachable on **stock PostgreSQL ≤14**, and on 15+
wherever `public` remains writable); where the audit function is owned by the app's own
role, the attacker can replace its body to drop writes and then restore the original source
byte-for-byte so that an object-diff finds nothing — while a write-vs-audit canary and a DDL
event-trigger still reveal the gap. A `current_setting`-gated branch yields a dormant,
per-session bypass that looks legitimate at rest, and a broad `INSERT` grant lets the role
fabricate backdated, identity-forged audit rows indistinguishable from genuine ones using
the audit table alone. Pinning the trigger's `search_path`, revoking `CREATE` on `public`,
correcting audit-object ownership, and — decisively — logging at the engine
(`pgaudit`/`log_statement`) with a hash-chained append-only sink each stop a specific
subset; only engine-level plus out-of-engine tamper-evidence closes the whole set. The
individual primitives are known (CVE-2018-1058; SECURITY DEFINER escalation); the
contribution is their composition into a self-defeating-audit threat model at *application*
privilege, which existing anti-forensics work — uniformly assuming a privileged adversary —
does not address.
