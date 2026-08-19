-- 3P: attribution poisoning (needs INSERT on the audit table). Fabricate a backdated, synthetic
-- identity decoupled from any real request.
USE labdb;
GO
GRANT INSERT ON dbo.audit_logged_actions TO app_user;
GO
EXECUTE AS USER='app_user';
  INSERT INTO dbo.audit_logged_actions(table_name,action,row_data,changed_by,client_host,logged_at)
  VALUES('app_accounts','U', N'[{"note":"sentinel-3P-decoy"}]',
         'ghost_user_42', '203.0.113.77', DATEADD(day,-3,SYSUTCDATETIME()));
REVERT;
GO
SELECT 'RES 3P ghost=' + CAST((SELECT COUNT(*) FROM dbo.audit_logged_actions WHERE changed_by='ghost_user_42' AND client_host='203.0.113.77') AS varchar(4))
     + ' backdated=' + CAST((SELECT COUNT(*) FROM dbo.audit_logged_actions WHERE changed_by='ghost_user_42' AND logged_at < DATEADD(day,-2,SYSUTCDATETIME())) AS varchar(4)) AS res;
GO
