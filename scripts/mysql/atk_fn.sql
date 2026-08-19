-- atk_fn.sql — MySQL analogue of the PostgreSQL search_path / catalog-shadow class (1A/1B).
-- Run as app_user. EXPECTED: N/A — MySQL-family has no search_path, built-in functions
-- (JSON_OBJECT) are resolved by the engine and cannot be transparently shadowed by a
-- user routine, and app_user lacks CREATE ROUTINE anyway. This block records the failure
-- and shows the sentinel write is still audited.
-- Attempt to plant a conflicting routine that would "capture" nothing:
CREATE FUNCTION labdb.JSON_OBJECT_SHADOW() RETURNS JSON RETURN NULL;   -- likely: no CREATE ROUTINE priv
-- Even a same-named routine cannot intercept the built-in call inside the trigger:
INSERT INTO labdb.app_accounts(holder,balance_cents) VALUES ('sentinel-FN',100);
