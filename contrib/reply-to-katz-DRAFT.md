# DRAFT reply to Jonathan Katz (pgsql-security) — NOT SENT

> Review and send under your own identity. Plain-text friendly.

Hi Jonathan,

Thank you — this is exactly the kind of correction I was hoping for.

You're right on the substance, and I'll adjust accordingly:

- At its core it applies the known CVE-2018-1058 best practices to one usage pattern, and I
  won't frame it as more than that. Agreed too that pgaudit (or an equivalent global
  mechanism) is the right answer for real production auditing, for the reasons you note.

- Your point about ownership is well taken, and it corrects my framing. If the audited role
  owns the audit function, the `search_path` angle is moot — it can simply rewrite the
  function — so that case isn't really an audit-integrity finding.

  In the more realistic case where the function is `SECURITY DEFINER` owned by a superuser
  with an unpinned `search_path`, the serious issue is the CVE-2018-1058 privilege-escalation
  path (the planted function runs as the owner), which subsumes and outweighs anything about
  audit fidelity. I was under-stating that; I'll reframe so the escalation risk is the
  headline and the audit-nulling is just one downstream symptom, not the main event.

I'd much rather put the effort where you suggested it's useful. Re-reading the recipes, both
already ship the important protections — the `SET search_path` clause on `if_modified_func()`,
the audit-schema `REVOKE`s, and the ownership note — so I wouldn't restate those. A hardening
addition that builds on what's there would focus on: (1) why the `SET search_path` clause is
load-bearing and must be kept when the function is adapted (the failure mode, and the
escalation risk you noted, become live the moment a copied variant drops it); (2) tightening
the 91plus pin, which includes `public` — e.g. installing `hstore` into a dedicated schema so
the path need not contain a PUBLIC-writable schema on ≤14; and (3) a short, fair note on the
trade-offs versus pgaudit (statement-level, no before/after row images) and out-of-engine
sinks. Framed around the `SECURITY DEFINER` escalation risk as the "why," per your point.

What's the preferred way to propose that — directly on the wiki, or run the wording by
-general (or here) first? I'll follow whatever process you'd like.

Thanks again for the guidance.

Best,
Thamilvendhan

[1] https://wiki.postgresql.org/wiki/Audit_trigger
[2] https://wiki.postgresql.org/wiki/Audit_trigger_91plus
