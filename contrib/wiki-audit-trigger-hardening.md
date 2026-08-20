# Hardening notes for the wiki "Audit trigger" recipes

Draft additions for [Audit_trigger](https://wiki.postgresql.org/wiki/Audit_trigger) and
[Audit_trigger_91plus](https://wiki.postgresql.org/wiki/Audit_trigger_91plus). **These build
on what the recipes already do** — they are *not* a claim that the shipped code is vulnerable.

> Internal notes (do NOT paste to the wiki): both recipes already pin the trigger function's
> `search_path` and already `REVOKE` on the audit schema. The old page's `audit.if_modified_func()`
> ships `SECURITY DEFINER SET search_path = pg_catalog, audit`; the 91plus page defers to
> `2ndQuadrant/audit-trigger` `audit.sql`, whose `audit.if_modified_func()` pins
> `SET search_path = pg_catalog, public`. So the contribution is (1) *keep the pin when adapting*,
> (2) *tighten the 91plus `public` inclusion*, (3) a fair note on alternatives. Remove any Zenodo
> DOI / "security team suggested this" preamble before posting.

---

## Security considerations

The audit trigger function is `SECURITY DEFINER`, and these recipes correctly ship it with a
`SET search_path` clause. That clause is load-bearing: under **CVE-2018-1058**, an unqualified
name inside a `SECURITY DEFINER` function with a mutable path is resolved against the *caller's*
`search_path`, so any role that can create an object in a schema preceding `pg_catalog` (classically
a PUBLIC-writable `public`) could make the function resolve to an attacker-supplied function or
operator. Because the function runs with the **owner's** privileges, if it is owned by a superuser
this is a privilege-escalation path (the planted code runs as that superuser) — which is more
serious than any audit concern. The pinned `search_path` in these recipes is exactly what prevents
that.

Three practical points for anyone deploying or adapting these recipes:

### 1. Keep the `SET search_path` clause when you adapt the code

The most common way this goes wrong is a copied or hand-modified variant that drops the
`SET search_path = …` clause (or adds an unqualified call to a helper in a writable schema). At that
moment the CVE-2018-1058 failure mode above becomes live. If you change the function, preserve the
pin, and prefer setting it at creation time:

```sql
CREATE FUNCTION audit.if_modified_func() RETURNS trigger AS $body$ … $body$
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, audit;
```

### 2. Tighten the 91plus pin so the path contains no PUBLIC-writable schema

The 91plus function pins to `pg_catalog, public` because it uses the `hstore` type/operators, and
the recipe installs `hstore` into `public`. On PostgreSQL ≤14 (and any cluster where `PUBLIC`
retains `CREATE` on `public`), that leaves a writable schema on the function's path. As shipped this
is not straightforwardly exploitable — `pg_catalog` precedes `public`, so built-ins are not
shadowable, and `hstore`'s own objects already occupy `public` — but it is cleaner to keep no
writable schema on the path at all. Install the extension in a dedicated schema and pin to it:

```sql
CREATE SCHEMA IF NOT EXISTS ext;
CREATE EXTENSION hstore SCHEMA ext;          -- or: ALTER EXTENSION hstore SET SCHEMA ext;
ALTER FUNCTION audit.if_modified_func() SET search_path = pg_catalog, ext;
```

Equivalently, on any version, remove the plant site: `REVOKE CREATE ON SCHEMA public FROM PUBLIC;`
(this is the **default** as of PostgreSQL 15). Note that while function names can be schema-qualified,
operators require the unwieldy `OPERATOR(schema.op)` form, so pinning the path is the more robust fix
than qualifying every reference.

### 3. Keep audit-object ownership away from the audited roles

These pages already advise that the application should not own the audited tables and that the app
role should have at most `USAGE` on the audit schema — worth emphasising: if a role that is itself
audited can `ALTER` or owns the audit function, auditing gives no integrity guarantee (it can rewrite
or disable it), and per the escalation point above you likely have a larger problem. Own the audit
schema, tables, and function with a dedicated role the audited roles can never modify.

### When to prefer engine-level auditing

For requirements that must resist a SQL-level adversary, [pgaudit](https://github.com/pgaudit/pgaudit)
logs at the executor, outside the reach of any role, and cannot be nulled by shadowing. The
trade-off is that pgaudit is **statement-level** and does not capture before/after **row images** —
which is the main reason to use these row-level triggers in the first place. So the two are
complementary: use the triggers for row history, and pgaudit (and/or shipping the audit stream to an
out-of-engine, append-only, tamper-evident sink) when you need logging the audited roles cannot
reach or alter.

### Detecting tampering (defence in depth)

An event trigger on `ddl_command_end` **and** `sql_drop` records DDL against audit-schema objects
(the `sql_drop` event is needed to catch `DROP`s, which `ddl_command_end` does not report); a periodic
canary comparing write counts on audited tables against audit-row counts surfaces gaps an object diff
alone can miss. Note that a superuser can disable or drop event triggers, so these detect
non-superuser tampering only.

---

*Reference: CVE-2018-1058, and the PostgreSQL documentation section "Writing SECURITY DEFINER
Functions Safely."*
