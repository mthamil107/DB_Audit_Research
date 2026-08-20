# DRAFT reply to Jonathan Katz (pgsql-security) — NOT SENT

> Review and send under your own identity. Plain-text friendly.

Hi Jonathan,

Thank you — this is exactly the kind of correction I was hoping for, and I appreciate you
taking the time.

You're right on all counts, and I'll adjust accordingly:

- It is fundamentally a restatement of the CVE-2018-1058 best practices applied to one
  usage pattern, and I won't frame it as more than that. Agreed too that pgaudit (or an
  equivalent global mechanism) is the right answer for real production auditing, for the
  reasons you note.

- Your point about ownership is well taken, and it corrects my framing. If the audited role
  owns the audit function, the `search_path` angle is moot — it can simply rewrite the
  function — so that case isn't really an audit-integrity finding. And in the more realistic
  case where the function is `SECURITY DEFINER` owned by a superuser with an unpinned
  `search_path`, the serious issue is the CVE-2018-1058 privilege-escalation path (the
  planted function runs as the owner), which subsumes and outweighs anything about audit
  fidelity. I was under-stating that; I'll reframe so the escalation risk is the headline and
  the audit-nulling is just one downstream symptom, not the main event.

I'd much rather put the effort where you suggested it's useful. I'll draft modern hardening
recommendations for the two wiki pages [1][2] — pin the trigger function's `search_path` (or
set it empty and schema-qualify), `REVOKE CREATE ON SCHEMA public FROM PUBLIC` (default on
15+), keep audit-object ownership away from the audited roles, and prefer pgaudit / an
out-of-engine append-only sink for anything with a real integrity requirement — with the
`SECURITY DEFINER` escalation risk called out as the primary reason, per your point.

What's the preferred way to propose those edits — directly on the wiki, or run the wording by
-general (or here) first? I'll follow whatever process you'd like.

Thanks again for the guidance.

Best,
Thamilvendhan

[1] https://wiki.postgresql.org/wiki/Audit_trigger
[2] https://wiki.postgresql.org/wiki/Audit_trigger_91plus
