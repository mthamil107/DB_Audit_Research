#!/usr/bin/env bash
# teardown.sh — drop the LocalDB test database. Leaves the LocalDB instance itself intact.
SQLCMD="/c/Program Files/Microsoft SQL Server/Client SDK/ODBC/170/Tools/Binn/SQLCMD.EXE"
"$SQLCMD" -S '(localdb)\MSSQLLocalDB' -E -b -Q \
  "IF DB_ID('labdb') IS NOT NULL BEGIN ALTER DATABASE labdb SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE labdb; END; PRINT 'labdb dropped';"
