# DRAFT — courtesy heads-up to security@postgresql.org

> **Status: NOT SENT.** This is a draft for you to review and send yourself, under
> your own identity. It is deliberately framed as a courtesy/heads-up, NOT a
> vulnerability report — the underlying primitives (CVE-2018-1058 search_path
> shadowing; SECURITY DEFINER escalation) are already documented, and the behaviors
> shown are documented behavior plus operator misconfiguration, not a new defect in
> PostgreSQL. Expect either no reply or a "this is expected behavior" response; both
> are fine and do not diminish the work.

**To:** security@postgresql.org
**Subject:** Courtesy heads-up (not a vuln report): lab study on trigger-audit blinding via documented search_path/ownership behavior

---

Hello PostgreSQL Security Team,

This is a courtesy note, not a vulnerability report. I want to be clear up front: I
do **not** believe this describes a new defect in PostgreSQL. Everything below is
documented behavior (CVE-2018-1058 `search_path` resolution; `SECURITY DEFINER`
function guidance) combined with operator-side misconfiguration. I'm flagging it only
in case you'd like awareness, or see it differently.

I ran a small, disposable, synthetic-data lab evaluating the integrity of the
widely-copied wiki "audit trigger" pattern (an `AFTER` row trigger calling a
`SECURITY DEFINER` function that captures rows via an unqualified `row_to_json`) when
the adversary is only the low-privilege application role (i.e., reached via SQL
injection — no superuser, no OS access). Reproduced on stock PostgreSQL 14 and 16.

Summary of what the lab shows (all under attacker == app role):

- Planting an **exact composite-type overload** `public.row_to_json(app.accounts)` in
  a writable `public` schema silently nulls captured rows when the trigger function's
  `search_path` is unpinned — because the exact rowtype match outranks the generic
  `row_to_json(record)` built-in. This is reachable on **stock PostgreSQL ≤14** (PUBLIC
  has CREATE on `public` by default) and needs a re-granted `public` on 15+. Pinning
  the trigger's `search_path` defeats it on every version.
- Where the audit function is owned by the application's own role (a common
  single-migration-role misconfiguration), the app role can replace the function body
  to drop writes and restore the original source verbatim, leaving a clean object diff.
- Related: a `current_setting`-gated dormant skip, and — with a broad INSERT grant —
  fabricated/backdated rows written directly into the audit table.

The point of the writeup is a **hardening checklist and defense evaluation** (pin
`search_path`, `REVOKE CREATE ON SCHEMA public`, correct audit-object ownership,
engine-level logging via pgaudit, and out-of-engine tamper-evident sinks), plus a
reproducible artifact. I plan to publish it as defensive research with all data
synthetic and no real system identified.

If any framing here is inaccurate, or if you'd prefer I adjust how the wiki pattern is
characterized, I'd genuinely welcome the correction before publication.

Thanks for everything you do,
Thamilvendhan Munirathinam
