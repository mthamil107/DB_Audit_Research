-- atk_2g.sql — session-variable-gated dormant trigger (MySQL analogue of Experiment 2).
-- Run as app_user. Preconditions: TRIGGER privilege AND INSERT on the audit table (a broad
-- grant). The latter is REQUIRED here because an app-owned (DEFINER=app_user) trigger cannot
-- write the root-owned audit table otherwise — so, unlike PostgreSQL, dormant selective
-- logging in MySQL needs the extra audit-INSERT grant. Gate on the user variable @app_maint.
DROP TRIGGER IF EXISTS labdb.accounts_ai;
DELIMITER //
CREATE DEFINER=CURRENT_USER TRIGGER labdb.accounts_ai AFTER INSERT ON labdb.app_accounts
FOR EACH ROW
BEGIN
  IF COALESCE(@app_maint,0) = 1 THEN
    SET @skipped = 1;                              -- dormant backdoor: silent skip
  ELSE
    INSERT INTO labdb.audit_logged_actions(table_name,action,row_data,changed_by,client_host)
    VALUES('app_accounts','I',
           JSON_OBJECT('id',NEW.id,'holder',NEW.holder,'balance_cents',NEW.balance_cents),
           USER(), @@hostname);
  END IF;
END//
DELIMITER ;
-- flag ON -> not logged
SET @app_maint = 1;
INSERT INTO labdb.app_accounts(holder,balance_cents) VALUES ('sentinel-2G-gated',200);
-- flag OFF -> logged (selectivity)
SET @app_maint = 0;
INSERT INTO labdb.app_accounts(holder,balance_cents) VALUES ('sentinel-2G-ctl',201);
