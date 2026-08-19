-- 40_snapshot.sql — capture the catalog state of the audit-relevant objects so the
-- harness can object-diff before vs. after an attack (RQ2: does restore leave residue?).
-- Usage: psql ... -v tag=before -f 40_snapshot.sql   (then tag=after)
-- Emits stable, greppable lines: SNAP <tag> <nsp> <proname> <owner> <md5-of-src> <proconfig>
\set ON_ERROR_STOP on
\if :{?tag} \else \set tag unset \endif
\c labdb
\pset tuples_only on
\pset format unaligned
\pset fieldsep ' '

SELECT 'SNAP'
     , :'tag'
     , n.nspname
     , p.proname
     , p.proowner::regrole::text
     , md5(pg_get_functiondef(p.oid))                       -- source fingerprint
     , COALESCE(array_to_string(p.proconfig,','),'-')       -- pinned search_path etc.
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('audit','public','evil')
ORDER BY n.nspname, p.proname;

-- trigger definitions on the audited table
SELECT 'SNAPTRG'
     , :'tag'
     , t.tgname
     , md5(pg_get_triggerdef(t.oid))
FROM pg_trigger t
JOIN pg_class c ON c.oid = t.tgrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'app' AND c.relname = 'accounts' AND NOT t.tgisinternal
ORDER BY t.tgname;

\pset tuples_only off
