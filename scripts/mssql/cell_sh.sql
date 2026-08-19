-- SH: name-resolution shadow probe. SQL Server has no search_path; unqualified names inside a
-- dbo-owned trigger resolve in dbo's schema (not the caller's), and the victim captures via the
-- built-in FOR JSON. So there is no caller-controlled shadow surface. Confirm the write logs.
USE labdb;
GO
EXECUTE AS USER='app_user';
  INSERT INTO dbo.app_accounts(holder,balance_cents) VALUES('sentinel-SH',100);
REVERT;
GO
SELECT 'RES SH logged=' + CAST((SELECT COUNT(*) FROM dbo.audit_logged_actions
  WHERE JSON_VALUE(row_data,'$[0].holder')='sentinel-SH') AS varchar(4)) AS res;
GO
