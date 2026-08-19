-- Defense: a DATABASE DDL trigger records CREATE/ALTER/DROP TRIGGER. It CATCHES an ALTER of the
-- audit trigger (1C) but NOT DISABLE/ENABLE (those raise no DDL event) -> an honest detection gap
-- that motivates SQL Server Audit / a write-vs-audit canary for the DISABLE primitive.
USE labdb;
GO
SET QUOTED_IDENTIFIER ON;
GO
IF OBJECT_ID('dbo.ddl_watch') IS NULL
CREATE TABLE dbo.ddl_watch(id INT IDENTITY PRIMARY KEY, evt SYSNAME, obj SYSNAME, who SYSNAME, seen_at DATETIME2 DEFAULT SYSUTCDATETIME());
GO
CREATE OR ALTER TRIGGER ddl_guard ON DATABASE WITH EXECUTE AS SELF FOR CREATE_TRIGGER, ALTER_TRIGGER, DROP_TRIGGER
AS
BEGIN
  SET NOCOUNT ON;
  INSERT INTO dbo.ddl_watch(evt,obj,who)
  VALUES(EVENTDATA().value('(/EVENT_INSTANCE/EventType)[1]','sysname'),
         EVENTDATA().value('(/EVENT_INSTANCE/ObjectName)[1]','sysname'), USER_NAME());
END
GO
GRANT ALTER ON dbo.app_accounts TO app_user;
GO
-- (a) DISABLE/ENABLE -- expected NOT to fire the DDL guard
EXECUTE AS USER='app_user';
  DISABLE TRIGGER dbo.accounts_audit ON dbo.app_accounts;
  ENABLE  TRIGGER dbo.accounts_audit ON dbo.app_accounts;
REVERT;
GO
SELECT 'RES DDLGUARD disable_caught=' + CAST((SELECT COUNT(*) FROM dbo.ddl_watch WHERE obj='accounts_audit') AS varchar(4)) AS res;
GO
-- (b) ALTER the trigger to a no-op -- expected to BE caught
EXECUTE AS USER='app_user';
  EXEC('ALTER TRIGGER dbo.accounts_audit ON dbo.app_accounts AFTER INSERT,UPDATE,DELETE AS BEGIN SET NOCOUNT ON; END');
REVERT;
GO
SELECT 'RES DDLGUARD alter_caught=' + CAST((SELECT COUNT(*) FROM dbo.ddl_watch WHERE obj='accounts_audit' AND evt='ALTER_TRIGGER') AS varchar(4)) AS res;
GO
