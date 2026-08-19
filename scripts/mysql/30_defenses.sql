-- 30_defenses.sql — hash-chained append-only sink (MySQL analogue of PG D-HC). Run as root.
-- (The engine-level defense is demonstrated separately via the general query log in the
--  orchestrator; correct-privilege and separate-DEFINER defenses are exercised by re-running
--  attacks with hardened grants.)
CREATE TABLE IF NOT EXISTS labdb.secure_log (
  seq       BIGINT AUTO_INCREMENT PRIMARY KEY,
  payload   JSON     NOT NULL,
  prev_hash CHAR(64) NOT NULL,
  this_hash CHAR(64) NOT NULL
);

DROP PROCEDURE IF EXISTS labdb.secure_append;
DROP FUNCTION  IF EXISTS labdb.secure_verify;
DELIMITER //
CREATE DEFINER=`root`@`localhost` PROCEDURE labdb.secure_append(IN p JSON)
BEGIN
  DECLARE ph CHAR(64);
  SELECT this_hash INTO ph FROM labdb.secure_log ORDER BY seq DESC LIMIT 1;
  IF ph IS NULL THEN SET ph = REPEAT('0',64); END IF;
  INSERT INTO labdb.secure_log(payload,prev_hash,this_hash)
  VALUES (p, ph, SHA2(CONCAT(ph, CAST(p AS CHAR)),256));
END//
CREATE DEFINER=`root`@`localhost` FUNCTION labdb.secure_verify() RETURNS BIGINT
  READS SQL DATA
BEGIN
  DECLARE done INT DEFAULT 0;
  DECLARE s BIGINT; DECLARE pl JSON; DECLARE prev CHAR(64); DECLARE th CHAR(64);
  DECLARE ph CHAR(64) DEFAULT REPEAT('0',64);
  DECLARE cur CURSOR FOR SELECT seq,payload,prev_hash,this_hash FROM labdb.secure_log ORDER BY seq;
  DECLARE CONTINUE HANDLER FOR NOT FOUND SET done=1;
  OPEN cur;
  read_loop: LOOP
    FETCH cur INTO s, pl, prev, th;
    IF done=1 THEN LEAVE read_loop; END IF;
    IF SHA2(CONCAT(ph, CAST(pl AS CHAR)),256) <> th OR prev <> ph THEN
      CLOSE cur; RETURN s;                         -- tamper detected at seq s
    END IF;
    SET ph = th;
  END LOOP;
  CLOSE cur;
  RETURN NULL;                                      -- intact
END//
DELIMITER ;
SELECT 'DEFENSES_INSTALLED' AS tag;
