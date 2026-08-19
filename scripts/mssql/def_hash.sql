-- Defense: hash-chained append-only sink (HASHBYTES SHA2_256).
USE labdb;
GO
IF OBJECT_ID('dbo.secure_log') IS NULL
CREATE TABLE dbo.secure_log(seq INT IDENTITY(1,1) PRIMARY KEY, payload NVARCHAR(MAX) NOT NULL,
                            prev_hash CHAR(64) NOT NULL, this_hash CHAR(64) NOT NULL);
GO
CREATE OR ALTER PROCEDURE dbo.secure_append @p NVARCHAR(MAX) AS
BEGIN
  DECLARE @ph CHAR(64)=(SELECT TOP 1 this_hash FROM dbo.secure_log ORDER BY seq DESC);
  IF @ph IS NULL SET @ph=REPLICATE('0',64);
  INSERT INTO dbo.secure_log(payload,prev_hash,this_hash)
  VALUES(@p,@ph,CONVERT(char(64),HASHBYTES('SHA2_256', CONVERT(varbinary(max),@ph+@p)),2));
END
GO
CREATE OR ALTER FUNCTION dbo.secure_verify() RETURNS INT AS
BEGIN
  DECLARE @ph CHAR(64)=REPLICATE('0',64), @bad INT=NULL;
  DECLARE @seq INT,@pl NVARCHAR(MAX),@prev CHAR(64),@th CHAR(64);
  DECLARE c CURSOR FOR SELECT seq,payload,prev_hash,this_hash FROM dbo.secure_log ORDER BY seq;
  OPEN c; FETCH NEXT FROM c INTO @seq,@pl,@prev,@th;
  WHILE @@FETCH_STATUS=0 AND @bad IS NULL
  BEGIN
    IF CONVERT(char(64),HASHBYTES('SHA2_256', CONVERT(varbinary(max),@ph+@pl)),2)<>@th OR @prev<>@ph SET @bad=@seq;
    SET @ph=@th; FETCH NEXT FROM c INTO @seq,@pl,@prev,@th;
  END
  CLOSE c; DEALLOCATE c; RETURN @bad;
END
GO
EXEC dbo.secure_append N'{"e":1}'; EXEC dbo.secure_append N'{"e":2}'; EXEC dbo.secure_append N'{"e":3}';
GO
SELECT 'RES HC intact=' + ISNULL(CAST(dbo.secure_verify() AS varchar(10)),'NULL') AS res;
INSERT INTO dbo.secure_log(payload,prev_hash,this_hash) VALUES(N'{"forged":true}',REPLICATE('0',64),'deadbeef');
SELECT 'RES HC tampered=' + ISNULL(CAST(dbo.secure_verify() AS varchar(10)),'NULL') AS res;
GO
