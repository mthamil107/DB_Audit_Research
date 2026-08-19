-- 1C-disable: the SQL-Server-specific primitive. With ALTER on the table, DISABLE TRIGGER
-- silently stops auditing; ENABLE restores. The trigger DEFINITION is byte-identical throughout
-- (only the is_disabled state flips, and it returns to 0) -> zero residue at rest.
USE labdb;
GO
GRANT ALTER ON dbo.app_accounts TO app_user;
GO
EXECUTE AS USER='app_user';
  DISABLE TRIGGER dbo.accounts_audit ON dbo.app_accounts;                            -- blind
  INSERT INTO dbo.app_accounts(holder,balance_cents) VALUES('sentinel-1D',100);      -- unlogged
  ENABLE TRIGGER dbo.accounts_audit ON dbo.app_accounts;                             -- restore
  INSERT INTO dbo.app_accounts(holder,balance_cents) VALUES('sentinel-1D-ctl',101);  -- logged
REVERT;
GO
SELECT 'RES 1Ddisable blinded_logged=' + CAST((SELECT COUNT(*) FROM dbo.audit_logged_actions WHERE JSON_VALUE(row_data,'$[0].holder')='sentinel-1D') AS varchar(4))
     + ' ctl_logged=' + CAST((SELECT COUNT(*) FROM dbo.audit_logged_actions WHERE JSON_VALUE(row_data,'$[0].holder')='sentinel-1D-ctl') AS varchar(4))
     + ' is_disabled_now=' + CAST((SELECT is_disabled FROM sys.triggers WHERE name='accounts_audit') AS varchar(2)) AS res;
GO
