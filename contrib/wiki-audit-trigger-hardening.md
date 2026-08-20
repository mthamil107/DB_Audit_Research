# Security hardening for the wiki "Audit trigger" recipes

Draft of a modern **Security considerations** section to add to
[Audit_trigger](https://wiki.postgresql.org/wiki/Audit_trigger) and
[Audit_trigger_91plus](https://wiki.postgresql.org/wiki/Audit_trigger_91plus),
per the suggestion from the PostgreSQL security team. Written for direct adaptation
to the wiki (MediaWiki markup can be applied when pasting).

---

## Security considerations

The trigger functions in this recipe are `SECURITY DEFINER` and, as written, run with an
**unpinned `search_path`** while calling **unqualified** built-ins (e.g. `row_to_json`,
`current_setting`, `hstore` operators). Under **CVE-2018-1058**, an unqualified name inside
such a function is resolved against the **caller's** `search_path`, so any role that can
create an object in a schema that precedes `pg_catalog` (classically a writable `public`)
can make the function resolve to an **attacker-supplied** function or operator instead of the
intended built-in.

For an audit trigger this has two consequences, the second more serious than the first:

1. **Audit integrity.** A planted `public.row_to_json(...)` that returns `NULL` (or a partial
   value) causes the captured `row_data` to be nulled — the audit row is still written, but
   its payload is worthless. The audit trail can thus be *silently degraded* by a
   low-privilege role, without touching the audit objects themselves.
2. **Privilege escalation (the bigger risk).** Because the function is `SECURITY DEFINER`,
   the planted function body executes **with the function owner's privileges**. If the audit
   function is owned by a superuser (common when audit objects are created by the DBA), the
   attacker's shadow function runs **as that superuser** — a full CVE-2018-1058 escalation,
   which subsumes and outweighs any audit concern. This is why the hardening below matters
   even if you do not care about audit fidelity per se.

**If the application's own role can `ALTER` or owns the audit function, auditing provides no
integrity guarantee at all** (the role can rewrite or disable it) — and, per the escalation
point above, you likely have a larger problem than auditing. Audit-object ownership must be
kept away from the audited roles.

### Recommended hardening (in priority order)

1. **Pin the function's `search_path`.** This is the single most effective fix and closes
   both risks above:
   ```sql
   ALTER FUNCTION audit.if_modified_func() SET search_path = pg_catalog, audit;
   -- or, most defensively, an empty path plus fully schema-qualified references:
   ALTER FUNCTION audit.if_modified_func() SET search_path = '';
   ```
   With an empty `search_path`, **schema-qualify every reference** in the function body
   (`pg_catalog.row_to_json(...)`, `pg_catalog.current_setting(...)`, etc.). Note that
   **operators and casts cannot be schema-qualified** with ordinary syntax, so pinning the
   path (rather than only qualifying function names) is the robust choice.

2. **Remove the plant site:** `REVOKE CREATE ON SCHEMA public FROM PUBLIC;` (this is the
   **default** as of PostgreSQL 15). On PostgreSQL ≤14, apply it explicitly. More generally,
   ensure no schema writable by application/low-privilege roles precedes `pg_catalog` on any
   relevant `search_path`.

3. **Own audit objects with a dedicated role the application can never `ALTER`.** Create the
   audit schema, tables, and functions as a role distinct from the application's
   migration/runtime role, and `REVOKE ALL ... FROM` the application role on those objects.
   Never let a single "does-everything" migration role own both the app and the audit
   objects.

4. **Prefer engine-level auditing for real requirements.** For most production systems,
   [pgaudit](https://github.com/pgaudit/pgaudit) (or an equivalent server-side mechanism)
   is the appropriate tool: it logs at the executor, outside the reach of any SQL-level role,
   and cannot be nulled by shadowing or by tampering with a trigger. Trigger-based auditing is
   convenient and close to the data, but it is **in-band** — it shares a trust boundary with
   the very statements it records.

5. **For high assurance, ship audit records to an out-of-engine, append-only sink** (e.g.
   logical decoding → an external collector) and make the stream **tamper-evident**
   (hash-chaining / signatures). An in-database log, however well-owned, can still be altered
   by a sufficiently privileged compromise; cryptographic tamper-evidence lets a separate
   verifier detect back-dating or alteration.

6. **Detective controls** (defence in depth): an event trigger on `ddl_command_end` that
   records DDL against audit-schema objects, and a periodic "canary" comparing write counts
   on audited tables against audit-row counts, will surface tampering that an object diff
   alone can miss.

### Minimal safe change to this recipe

At the very least, add to the recipe:

```sql
-- pin the search_path of every audit trigger function shipped by this recipe
ALTER FUNCTION audit.if_modified_func()  SET search_path = pg_catalog, audit;
-- (and REVOKE CREATE ON SCHEMA public FROM PUBLIC; on PostgreSQL <= 14)
```

and a note that the audit schema/objects should be **owned by a role distinct from the
audited application roles**.

---

*Rationale, references, and a reproducible lab demonstrating each point are archived at
Zenodo (DOI: 10.5281/zenodo.22004478). Primary references: CVE-2018-1058 and the PostgreSQL
documentation on "Writing SECURITY DEFINER Functions Safely."*
