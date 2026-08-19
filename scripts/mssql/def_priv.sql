-- Defense: no ALTER on the table -> app cannot DISABLE/replace the trigger.
USE labdb;
GO
EXECUTE AS USER='app_user';
  BEGIN TRY DISABLE TRIGGER dbo.accounts_audit ON dbo.app_accounts; PRINT 'UNEXPECTED: disable succeeded';
  END TRY BEGIN CATCH PRINT 'disable-denied: '+ERROR_MESSAGE(); END CATCH;
  INSERT INTO dbo.app_accounts(holder,balance_cents) VALUES('sentinel-DPRIV',100);
REVERT;
GO
SELECT 'RES DPRIV logged=' + CAST((SELECT COUNT(*) FROM dbo.audit_logged_actions
  WHERE JSON_VALUE(row_data,'$[0].holder')='sentinel-DPRIV') AS varchar(4)) AS res;
GO
