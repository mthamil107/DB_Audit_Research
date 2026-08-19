-- 10_victim.sql — SQL Server trigger-based audit victim (LocalDB / SQL Server). Run as dbo/sa.
-- SQL Server analogue of the wiki pattern: an AFTER trigger relies on OWNERSHIP CHAINING
-- (trigger, business table, and audit table all owned by dbo) so a low-privilege writer is
-- audited without any direct grant on the audit table — the classic SQL Server "definer"
-- mechanism. Each affected row is captured as JSON (built-in FOR JSON). USER_NAME() records
-- the real invoking database principal. Synthetic data only.
-- The low-privilege attacker is modelled by a WITHOUT LOGIN user impersonated via EXECUTE AS
-- USER (LocalDB is Windows-auth only); permission checks are enforced in that user's context.
SET NOCOUNT ON;
IF DB_ID('labdb') IS NOT NULL
BEGIN
  ALTER DATABASE labdb SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
  DROP DATABASE labdb;
END
GO
CREATE DATABASE labdb;
GO
USE labdb;
GO
-- low-privilege app principal (simulated SQLi context)
CREATE USER app_user WITHOUT LOGIN;
GO
CREATE TABLE dbo.app_accounts (
  id            INT IDENTITY(1,1) PRIMARY KEY,
  holder        NVARCHAR(200) NOT NULL,
  balance_cents BIGINT NOT NULL DEFAULT 0
);
GO
CREATE TABLE dbo.audit_logged_actions (
  event_id    INT IDENTITY(1,1) PRIMARY KEY,
  table_name  SYSNAME       NOT NULL,
  action      CHAR(1)       NOT NULL,
  row_data    NVARCHAR(MAX),
  changed_by  SYSNAME       NOT NULL,
  client_host SYSNAME       NULL,
  logged_at   DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME()
);
GO
CREATE TRIGGER dbo.accounts_audit ON dbo.app_accounts
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
  SET NOCOUNT ON;
  DECLARE @act CHAR(1) =
    CASE WHEN EXISTS(SELECT 1 FROM inserted) AND EXISTS(SELECT 1 FROM deleted) THEN 'U'
         WHEN EXISTS(SELECT 1 FROM inserted) THEN 'I' ELSE 'D' END;
  DECLARE @json NVARCHAR(MAX) =
    CASE WHEN @act='D' THEN (SELECT * FROM deleted  FOR JSON PATH)
         ELSE               (SELECT * FROM inserted FOR JSON PATH) END;
  -- ownership chaining (dbo->dbo) lets this INSERT succeed for any low-priv writer:
  INSERT INTO dbo.audit_logged_actions(table_name,action,row_data,changed_by,client_host)
  VALUES('app_accounts',@act,@json,USER_NAME(),HOST_NAME());
END
GO
-- app grants — ONLY DML on the business table by default
GRANT SELECT,INSERT,UPDATE,DELETE ON dbo.app_accounts TO app_user;
GO
-- baseline sanity: a dbo write should log
INSERT INTO dbo.app_accounts(holder,balance_cents) VALUES ('synthetic-baseline-dba',1);
GO
SELECT 'BASELINE_AUDIT_COUNT n=' + CAST(COUNT(*) AS varchar(10)) AS res
FROM dbo.audit_logged_actions WHERE JSON_VALUE(row_data,'$[0].holder')='synthetic-baseline-dba';
GO
