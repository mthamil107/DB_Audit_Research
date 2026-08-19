-- 10_victim.sql — MySQL-family (MariaDB) trigger-based audit victim. Run as root.
-- Analogue of the PostgreSQL wiki pattern: DEFINER triggers (run with the definer's
-- privileges) capture each write as JSON into a root-owned audit table, so a low-privilege
-- writer can be audited. Synthetic data only.
DROP DATABASE IF EXISTS labdb;
CREATE DATABASE labdb;

DROP USER IF EXISTS 'app_user'@'%';
CREATE USER 'app_user'@'%' IDENTIFIED BY 'app_pw';

-- business table
CREATE TABLE labdb.app_accounts (
  id            BIGINT AUTO_INCREMENT PRIMARY KEY,
  holder        VARCHAR(200) NOT NULL,
  balance_cents BIGINT NOT NULL DEFAULT 0
);

-- audit store (root-owned; app_user has NO rights on it by default)
CREATE TABLE labdb.audit_logged_actions (
  event_id    BIGINT AUTO_INCREMENT PRIMARY KEY,
  table_name  VARCHAR(128) NOT NULL,
  action      CHAR(1)      NOT NULL,          -- I/U/D
  row_data    JSON,                            -- captured via built-in JSON_OBJECT()
  changed_by  VARCHAR(200) NOT NULL,           -- USER() = real invoker, even inside DEFINER ctx
  client_host VARCHAR(200),
  logged_at   DATETIME     NOT NULL DEFAULT NOW()
);

-- DEFINER triggers owned by root@localhost. Triggers execute with the DEFINER's privileges,
-- so the INSERT into the root-owned audit table succeeds even when app_user fires them.
DELIMITER //
CREATE DEFINER=`root`@`localhost` TRIGGER labdb.accounts_ai AFTER INSERT ON labdb.app_accounts
FOR EACH ROW
  INSERT INTO labdb.audit_logged_actions(table_name,action,row_data,changed_by,client_host)
  VALUES('app_accounts','I',
         JSON_OBJECT('id',NEW.id,'holder',NEW.holder,'balance_cents',NEW.balance_cents),
         USER(), @@hostname)//
CREATE DEFINER=`root`@`localhost` TRIGGER labdb.accounts_au AFTER UPDATE ON labdb.app_accounts
FOR EACH ROW
  INSERT INTO labdb.audit_logged_actions(table_name,action,row_data,changed_by,client_host)
  VALUES('app_accounts','U',
         JSON_OBJECT('id',NEW.id,'holder',NEW.holder,'balance_cents',NEW.balance_cents),
         USER(), @@hostname)//
CREATE DEFINER=`root`@`localhost` TRIGGER labdb.accounts_ad AFTER DELETE ON labdb.app_accounts
FOR EACH ROW
  INSERT INTO labdb.audit_logged_actions(table_name,action,row_data,changed_by,client_host)
  VALUES('app_accounts','D',
         JSON_OBJECT('id',OLD.id,'holder',OLD.holder,'balance_cents',OLD.balance_cents),
         USER(), @@hostname)//
DELIMITER ;

-- app grants — ONLY DML on the business table by default
GRANT SELECT,INSERT,UPDATE,DELETE ON labdb.app_accounts TO 'app_user'@'%';

-- baseline sanity: a root write should log
INSERT INTO labdb.app_accounts(holder,balance_cents) VALUES ('synthetic-baseline-dba',1);
SELECT 'BASELINE_AUDIT_COUNT' AS tag,
       COUNT(*) AS n FROM labdb.audit_logged_actions
       WHERE JSON_UNQUOTE(JSON_EXTRACT(row_data,'$.holder'))='synthetic-baseline-dba';
