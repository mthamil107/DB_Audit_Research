-- 2G: session-gated dormant trigger (needs ALTER on the table). Because ALTER TRIGGER does NOT
-- change ownership, ownership chaining survives, so the dormant trigger still logs when the flag
-- is off WITHOUT any extra audit-INSERT grant -- easy dormancy, like PostgreSQL (unlike MySQL).
USE labdb;
GO
GRANT ALTER ON dbo.app_accounts TO app_user;
GO
EXECUTE AS USER='app_user';
  EXEC('ALTER TRIGGER dbo.accounts_audit ON dbo.app_accounts AFTER INSERT, UPDATE, DELETE AS
  BEGIN
    SET NOCOUNT ON;
    IF CONVERT(int, ISNULL(SESSION_CONTEXT(N''maint''),0)) = 1 RETURN;   -- dormant skip
    DECLARE @act CHAR(1) = CASE WHEN EXISTS(SELECT 1 FROM inserted) AND EXISTS(SELECT 1 FROM deleted) THEN ''U''
                                WHEN EXISTS(SELECT 1 FROM inserted) THEN ''I'' ELSE ''D'' END;
    DECLARE @json NVARCHAR(MAX) = CASE WHEN @act=''D'' THEN (SELECT * FROM deleted FOR JSON PATH)
                                       ELSE (SELECT * FROM inserted FOR JSON PATH) END;
    INSERT INTO dbo.audit_logged_actions(table_name,action,row_data,changed_by,client_host)
    VALUES(''app_accounts'',@act,@json,USER_NAME(),HOST_NAME());
  END');
  EXEC sp_set_session_context @key=N'maint', @value=1;
  INSERT INTO dbo.app_accounts(holder,balance_cents) VALUES('sentinel-2G-gated',200);  -- skipped
  EXEC sp_set_session_context @key=N'maint', @value=0;
  INSERT INTO dbo.app_accounts(holder,balance_cents) VALUES('sentinel-2G-ctl',201);    -- logged
REVERT;
GO
SELECT 'RES 2G gated_logged=' + CAST((SELECT COUNT(*) FROM dbo.audit_logged_actions WHERE JSON_VALUE(row_data,'$[0].holder')='sentinel-2G-gated') AS varchar(4))
     + ' ctl_logged=' + CAST((SELECT COUNT(*) FROM dbo.audit_logged_actions WHERE JSON_VALUE(row_data,'$[0].holder')='sentinel-2G-ctl') AS varchar(4)) AS res;
GO
